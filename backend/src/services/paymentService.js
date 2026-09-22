// services/paymentService.js — M5: payment + double-spend detection
//
// v3 §3.1 + §四-4 + professor's M5 design decisions:
//   1. token transmission: structured fields { serial, amount, R_prime, s_prime }
//      (NOT a JSON blob) so field-level validation can 400 each malformed field
//      individually before reaching the (ms-level) curve operations.
//   2. initial balance: customer registers with balance=100 (see userService.js)
//   3. merchant pre-verification: M6 scope, NOT done here.
//
// Professor's M5 隐患 (all addressed):
//   H1 (畸形 token DoS): formatGate rejects at string level BEFORE verifySig.
//       Tests: serial 63 hex → 400; R' prefix 04 → 400; s' 63 hex → 400;
//       amount=0 → 400.
//   H2 (token_hash 编码): SHA256 over Buffer.concat([serial, R', s']) — bytes
//       level, NOT hex strings. Prevents 0x0A/0x0a casing ambiguity from
//       producing two distinct token_hash values for the same logical token,
//       which would let an attacker double-spend by re-casing the hex.
//   H3 (双花 vs 重试): same merchant re-submitting the same token gets 409
//       DOUBLE_SPEND — this is correct eCash semantics (token consumed),
//       NOT a bug. Tests distinguish:
//         - two different merchants concurrent same token → 200 + 409 (true double-spend)
//         - same merchant re-submitting → 409 (retry semantics)
//
// Core design 铁律 (professor M5):
//   verifySig 在事务外 (只读曲线运算，无锁) → BEGIN IMMEDIATE 只包
//   "SELECT serial → 409 → INSERT spent_coins + UPDATE merchant.balance"
//   三个写动作 → 任何一步失败整体回滚，merchant.balance 与 spent_coins 永不分裂。
//
// ISOLATION.md hard invariants enforced here:
//   §一-2: merchant.balance is ONLY incremented by /payment (processPayment).
//   §一-6: spent_coins.serial PRIMARY KEY + idx_sc_token_hash UNIQUE =
//          double-spend defense in depth.

import { createHash } from 'node:crypto';
import { runImmediateTx } from '../models/db.js';
import { getPublicKey } from './bankKeyService.js';
import { verifySig } from '../crypto/server/schnorrBlind.js';
import { n, bytesToScalar, isValidScalar } from '../crypto/server/curve.js';
import { hexToBytes } from '../utils/hex.js';

/**
 * Error carrying an HTTP status. Routes catch this and map to res.status().
 * Anything thrown that isn't a PaymentError is treated as 500.
 */
export class PaymentError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'PaymentError';
    this.status = status;
    this.code = code;
  }
}

// Hex charset regex (case-insensitive). Used by the format gate to reject
// non-hex characters before any byte-level parsing.
const HEX_RE = /^[0-9a-fA-F]+$/;

/**
 * Format gate (H1): cheap string-level validation BEFORE curve operations.
 *
 * Why this exists: verifySig's internal decodePoint throws → catch → false
 * on malformed points, but each call is ms-level. A malicious merchant
 * flooding /api/payment with garbage tokens could DoS the curve math. The
 * format gate rejects at the string level (no curve ops) so malformed
 * tokens never reach verifySig.
 *
 * Also: the professor flagged that "signature invalid" and "params malformed"
 * sharing the same 400 status is GOOD — it prevents an oracle distinguishing
 * the two. So both paths return 400; we just route malformed ones through
 * the cheap gate first.
 *
 * @param {{serial:unknown, amount:unknown, R_prime:unknown, s_prime:unknown}} tok
 * @returns {{serialBytes:Uint8Array, RPrimeBytes:Uint8Array, sPrimeBytes:Uint8Array, sPrime:bigint}}
 * @throws {PaymentError} 400 MALFORMED_TOKEN on any failure
 */
function formatGate(tok) {
  const { serial, amount, R_prime, s_prime } = tok;

  // ── string-level checks (no curve math, no allocations) ──
  if (typeof serial !== 'string' || serial.length !== 64 || !HEX_RE.test(serial)) {
    throw new PaymentError(400, 'MALFORMED_TOKEN', 'serial must be 64 hex chars');
  }
  if (typeof R_prime !== 'string' || R_prime.length !== 66 || !HEX_RE.test(R_prime)) {
    throw new PaymentError(400, 'MALFORMED_TOKEN', 'R_prime must be 66 hex chars');
  }
  // R' prefix must be 0x02 or 0x03 (compressed-point even/odd y parity).
  // Rejecting 0x04 (uncompressed) and 0x06/0x07 (hybrid) here keeps verifySig
  // from ever touching an off-format point.
  const rPrefix = R_prime.slice(0, 2).toLowerCase();
  if (rPrefix !== '02' && rPrefix !== '03') {
    throw new PaymentError(400, 'MALFORMED_TOKEN',
      "R_prime prefix must be '02' or '03' (compressed)");
  }
  if (typeof s_prime !== 'string' || s_prime.length !== 64 || !HEX_RE.test(s_prime)) {
    throw new PaymentError(400, 'MALFORMED_TOKEN', 's_prime must be 64 hex chars');
  }
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new PaymentError(400, 'MALFORMED_TOKEN', 'amount must be a positive integer');
  }

  // ── byte-level parse (hexToBytes already validated length is even) ──
  const serialBytes = hexToBytes(serial);
  const RPrimeBytes = hexToBytes(R_prime);
  const sPrimeBytes = hexToBytes(s_prime);

  // ── scalar range check on s' ──
  // verifySig would re-check via isValidScalar, but rejecting here keeps the
  // format gate as the sole rejector for malformed scalars (no curve ops).
  // s' must be in [1, n-1] to be a valid Schnorr scalar.
  const sPrime = bytesToScalar(sPrimeBytes);
  if (!isValidScalar(sPrime)) {
    throw new PaymentError(400, 'MALFORMED_TOKEN',
      's_prime must be a valid scalar in [1, n-1]');
  }

  return { serialBytes, RPrimeBytes, sPrimeBytes, sPrime };
}

/**
 * Compute token_hash = SHA256(serial ‖ R' ‖ s') with BYTES-level concat (H2).
 *
 * Why bytes, not hex strings: hex encoding has casing ambiguity (0x0A vs 0x0a)
 * and variable leading-zero behavior. If we hashed hex strings, an attacker
 * could re-case the same token to produce a DIFFERENT token_hash and bypass
 * the UNIQUE index — re-spending the same logical coin. Hashing the raw
 * bytes eliminates that attack surface entirely: same bytes → same hash,
 * regardless of how the merchant serialized them on the wire.
 *
 * @param {Uint8Array} serialBytes   32 bytes
 * @param {Uint8Array} rPrimeBytes   33 bytes
 * @param {Uint8Array} sPrimeBytes   32 bytes
 * @returns {Uint8Array} 32-byte SHA256 digest
 */
function computeTokenHash(serialBytes, rPrimeBytes, sPrimeBytes) {
  return new Uint8Array(
    createHash('sha256')
      .update(Buffer.concat([serialBytes, rPrimeBytes, sPrimeBytes]))
      .digest(),
  );
}

/**
 * Process a payment: verify the token signature, then atomically deposit it
 * to the merchant's balance. Double-spend attempts (same serial OR same
 * token_hash) are rejected with 409 inside a BEGIN IMMEDIATE transaction.
 *
 * Flow (v3 §四-4 + professor's M5 铁律):
 *   1. formatGate — reject malformed at string level (H1, DoS defense)
 *   2. verifySig — Schnorr blind signature verification (OUTSIDE tx,
 *        read-only curve math, no lock needed)
 *   3. token_hash = SHA256(serial ‖ R' ‖ s') — bytes concat (H2)
 *   4. BEGIN IMMEDIATE:
 *        SELECT serial FROM spent_coins → exists → 409 DOUBLE_SPEND
 *        INSERT spent_coins (serial, amount, deposited_to, token_hash)
 *          (token_hash UNIQUE → 409 on collision even with different serial)
 *        UPDATE merchant.balance += amount
 *      COMMIT — all three writes atomic, no TOCTOU window for double-debit
 *
 * ISOLATION §一-2: merchant.balance is ONLY mutated here (incremented).
 * ISOLATION §一-6: spent_coins.serial PRIMARY KEY + token_hash UNIQUE =
 *                 double-spend guard at the DB level.
 *
 * Retry semantics (H3): a merchant that re-submits the SAME token after a
 * successful deposit gets 409 DOUBLE_SPEND — this is correct eCash semantics
 * (token is consumed on first successful deposit). Network retry UX is a
 * frontend concern (M6).
 *
 * @param {{merchant_id:number, serial:string, amount:number, R_prime:string, s_prime:string}} args
 * @returns {{deposited:number, new_balance:number}}
 * @throws {PaymentError} 400 MALFORMED_TOKEN / 400 SIGNATURE_INVALID / 409 DOUBLE_SPEND
 */
export function processPayment({ merchant_id, serial, amount, R_prime, s_prime }) {
  // 1. Format gate (H1): reject malformed before curve operations.
  const { serialBytes, RPrimeBytes, sPrimeBytes, sPrime } = formatGate({
    serial,
    amount,
    R_prime,
    s_prime,
  });

  // 2. Verify signature (OUTSIDE transaction — only read-only curve math).
  //    Failure here means the token is either tampered (e.g., amount bumped
  //    after signing) or unblinded wrong. Either way: 400 SIGNATURE_INVALID.
  //    We deliberately use the SAME 400 as MALFORMED_TOKEN to avoid leaking
  //    the distinction (oracle defense, per professor's M5 note).
  const publicKey = getPublicKey();
  const ok = verifySig(RPrimeBytes, sPrime, serialBytes, amount, publicKey);
  if (!ok) {
    throw new PaymentError(400, 'SIGNATURE_INVALID',
      'signature verification failed — token is forged or tampered');
  }

  // 3. token_hash with bytes-level concat (H2).
  const tokenHash = computeTokenHash(serialBytes, RPrimeBytes, sPrimeBytes);

  // 4. Atomic deposit (BEGIN IMMEDIATE holds the write lock for the full block).
  //    Any throw inside → transaction rolls back, no partial state.
  return runImmediateTx((db) => {
    // Primary double-spend guard: same serial already spent → 409.
    const existing = db.prepare(
      `SELECT 1 FROM spent_coins WHERE serial = ?`,
    ).get(Buffer.from(serialBytes));
    if (existing) {
      throw new PaymentError(409, 'DOUBLE_SPEND',
        'this token has already been spent');
    }

    // Insert spent_coins row. idx_sc_token_hash UNIQUE is the belt-and-suspenders
    // guard for the corner case where two different serials produce the same
    // (R', s') tuple (shouldn't happen under correct protocol, but the UNIQUE
    // index makes it a DB-level invariant — see schema.sql comment).
    try {
      db.prepare(
        `INSERT INTO spent_coins (serial, amount, deposited_to, token_hash)
         VALUES (?, ?, ?, ?)`,
      ).run(
        Buffer.from(serialBytes),
        amount,
        merchant_id,
        Buffer.from(tokenHash),
      );
    } catch (e) {
      // UNIQUE violation on token_hash (different serial, same (R', s')).
      // The professor's M5 acceptance #4 explicitly tests this fallback.
      if (e.message && e.message.includes('UNIQUE')) {
        throw new PaymentError(409, 'DOUBLE_SPEND',
          "token_hash collision — same (R', s') already spent under a different serial");
      }
      throw e; // re-throw anything else → route maps to 500
    }

    // Credit merchant balance. ISOLATION §一-2: only /payment mutates merchant.balance.
    db.prepare(
      `UPDATE users SET balance = balance + ? WHERE id = ?`,
    ).run(amount, merchant_id);

    const row = db.prepare(
      `SELECT balance FROM users WHERE id = ?`,
    ).get(merchant_id);
    if (!row) {
      // Defensive: merchant row vanished mid-tx (shouldn't happen — FK enforced).
      throw new PaymentError(500, 'MERCHANT_NOT_FOUND', 'merchant account vanished mid-transaction');
    }

    return { deposited: amount, new_balance: row.balance };
  });
}
