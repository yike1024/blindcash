// services/paymentService.js — M5: payment + double-spend detection
//
// v3 §3.1 + §四-4 + professor's M5 design decisions:
//   1. token transmission: structured fields { serial, amount, R_prime, s_prime }
//      (NOT a JSON blob) so field-level validation can 400 each malformed field
//      individually before reaching the (ms-level) curve operations.
//   2. initial balance: customer registers with balance=0 (Phase 1); tests
//      fund via fundUser() → /api/bank/deposit (see userService.js)
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
import { getActivePublicKey, getPublicKeyByVersion, getActiveKeyVersion, getDenominationByVersion, BankKeyError } from './bankKeyService.js';
import { DENOMINATIONS } from '../config/bank.js';
import { verifySig } from '../crypto/server/schnorrBlind.js';
import { n, bytesToScalar, isValidScalar } from '../crypto/server/curve.js';
import { hexToBytes } from '../utils/hex.js';
import { recordTransaction } from './transactionService.js';
import { assertInvariant, runInvariantCheckedTx } from './bankReserveService.js';
import { logAction } from './auditService.js';

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
 * @param {{merchant_id:number, serial:string, amount:number, R_prime:string, s_prime:string, key_id?:number}} args
 *   args.key_id — optional, token v2 schema field. Phase 3 多密钥轮换时
 *     用来查对应版本的公钥验签；Phase 1 单密钥时 getPublicKeyByVersion(v)
 *     始终返回同一把。缺省时走 getActivePublicKey()（前向兼容老 token）。
 * @returns {{deposited:number, new_balance:number}}
 * @throws {PaymentError} 400 MALFORMED_TOKEN / 400 SIGNATURE_INVALID / 409 DOUBLE_SPEND
 */
export function processPayment({ merchant_id, serial, amount, R_prime, s_prime, key_id }) {
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
  //
  //    Note on oracle surface: HTTP status is uniformly 400 for both
  //    MALFORMED_TOKEN and SIGNATURE_INVALID (an attacker can't distinguish
  //    "format bad" from "signature bad" via the status code alone — both
  //    look like 400). The error CODE is kept distinct solely for debug
  //    readability (a legitimate merchant hitting a 400 wants to know which
  //    check failed). This is not an oracle: the attacker already knows
  //    whether they constructed a well-formed token.
  //
  //    Phase 3 (v5 §三 3.2 落地)：service 层用
  //    `getPublicKeyByVersion(key_id)` 查对应版本公钥验签。key_id 缺省
  //    （旧 token 或 redeem 路由未传）时 fallback 到 getActivePublicKey()。
  //    BankKeyError (KEY_RETIRED / KEY_NOT_FOUND) → PaymentError 映射。
  let publicKey;
  try {
    publicKey = (key_id != null)
      ? getPublicKeyByVersion(key_id)
      : getActivePublicKey();
  } catch (e) {
    if (e instanceof BankKeyError) {
      throw new PaymentError(e.status, e.code, e.message);
    }
    throw e;
  }
  const ok = verifySig(RPrimeBytes, sPrime, serialBytes, amount, publicKey);
  if (!ok) {
    throw new PaymentError(400, 'SIGNATURE_INVALID',
      'signature verification failed — token is forged or tampered');
  }

  // 3. token_hash with bytes-level concat (H2).
  const tokenHash = computeTokenHash(serialBytes, RPrimeBytes, sPrimeBytes);

  // 4. Atomic deposit (BEGIN IMMEDIATE holds the write lock for the full block).
  //    Any throw inside → transaction rolls back, no partial state.
  //    Phase 3: runInvariantCheckedTx wraps with audit on invariant_violation.
  return runInvariantCheckedTx((db) => {
    // Primary double-spend guard: same serial already spent → 409.
    const existing = db.prepare(
      `SELECT 1 FROM spent_coins WHERE serial = ?`,
    ).get(Buffer.from(serialBytes));
    if (existing) {
      throw new PaymentError(409, 'DOUBLE_SPEND',
        'this token has already been spent');
    }

    // Phase 3 (v5 §三 3.2)：spent_coins INSERT 带 key_version 列，记录
    // 这枚 token 是用哪个 key_version 签发的。key_id 缺省时用当前 active
    // key_version（前向兼容旧 token 路径）。
    const keyVersion = (key_id != null) ? key_id : getActiveKeyVersion();
    // Phase 6.1: 从 key_id 反查 denomination，记录到 spent_coins 用于
    // 6.3 匿名集分析（按 denom + key_version 分组统计）。
    // key_id 缺省时（旧 token 路径）denom=1。
    const denomination = (key_id != null) ? getDenominationByVersion(key_id) : 1;

    // Insert spent_coins row. idx_sc_token_hash UNIQUE is the belt-and-suspenders
    // guard for the corner case where two different serials produce the same
    // (R', s') tuple (shouldn't happen under correct protocol, but the UNIQUE
    // index makes it a DB-level invariant — see schema.sql comment).
    try {
      db.prepare(
        `INSERT INTO spent_coins (serial, amount, deposited_to, token_hash, key_version, denomination)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(
        Buffer.from(serialBytes),
        amount,
        merchant_id,
        Buffer.from(tokenHash),
        keyVersion,
        denomination,
      );
    } catch (e) {
      // UNIQUE violation on token_hash (different serial, same (R', s')).
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

    // M7: 写一笔 deposit 流水，让商户在 /history 看到收款去向。
    // counterparty = NULL（Chaum 盲现：token 匿名，商户无法知道付款人）。
    recordTransaction(db, {
      user_id: merchant_id,
      kind: 'deposit',
      amount,
      counterparty: null,
      serial: serialBytes,
      session_id: null,
      note: '收款',
    });

    // Phase 1 (v5 §三 1.3)：total_redeemed += amount，与商户收款在同一
    // BEGIN IMMEDIATE 内。语义上 total_redeemed = "所有 token 兑付总量"
    // （包括商户收款和用户退币——电子货币一旦兑付就退出流通）。
    db.prepare(
      `UPDATE bank_reserve
          SET total_redeemed = total_redeemed + ?,
              updated_at = CURRENT_TIMESTAMP
        WHERE id = 1`
    ).run(amount);

    // Phase 3 (N1 落地)：payment 审计日志写在事务内
    logAction({
      actor_id: merchant_id,
      action: 'payment',
      amount,
      target: Buffer.from(serialBytes).toString('hex').slice(0, 16) + '...',
      meta: JSON.stringify({ key_version: keyVersion }),
      db,
    });

    // assertInvariant 在事务内调用——失败时整个 BEGIN IMMEDIATE 回滚，
    // 不会出现 spent_coins 插了但 total_redeemed 没加的半状态。
    assertInvariant(db);

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

// ─────────────────────────────────────────────────────────────────────
// Phase 6.2: redeem-split — 部分取款 / 找零兑付（教学化简化方案）
// ─────────────────────────────────────────────────────────────────────
//
// v6 §四 6.2 落地：用户持有大面额 token（如 50 BC），希望拆成更小面额
// 的零钱使用。Chaum 协议下真正的"找零"需要银行发行新 token，必须走完整
// 4-move 取款流程——不存在"原 token 切一刀"的简单拆分。
//
// 本接口的简化语义：
//   1. 验证原 token（formatGate + verifySig）
//   2. 校验 amount 能被 split_denomination 整除（否则拆分不对齐）
//   3. 原子事务：
//      - INSERT spent_coins（denomination 列 = split_denomination，教学化
//        标记"这笔兑付在概念上等价于 amount/split_denomination 枚小币"）
//      - UPDATE users.balance += amount（全额退到账户）
//      - recordTransaction(kind='redeem_split', note=split 信息)
//      - assertInvariant
//   4. 用户随后可另走 4-move 取款流程取 split_denomination 面额的新 token
//
// **隐私局限（必须文档化，见 limitations 数组）**：
//   1. 这不是真正的 Chaum 找零——银行把大额 token 全额退到账户，
//      用户需另走 4-move 取款获得新面额 token。
//   2. spent_coins 按 split_denomination 记账仅是教学展示，不改变 Chaum
//      协议语义；实际生产系统的找零协议需商户侧协议（如 Brands' fair
//      cash [1]），本系统不实现。
//   3. 银行可观察到"大额兑付 + 后续小额取款"模式，存在时间侧信道——
//      攻击者可借此缩小匿名集（参考 Chaum 1985 [2] §"Privacy"）。
//   4. 真正的找零协议会让商户参与：顾客给 50 BC token 购 30 BC 商品，
//      商户找 20 BC token；本系统不实现商户侧找零协议，简化教学。
//
// 文献参考：
//   [1] Brands S. 1993. "Untraceable Off-Line Cash in Wallets with Observers".
//       Crypto'93. §3 — 钱包观察者协议，让商户侧参与找零的早期方案。
//   [2] Chaum D. 1985. "Security Without Identification: Transaction Systems
//       to Make Big Brother Obsolete". CACM 28(10). §"Privacy" — 时间侧信道
//       对匿名集的削弱，本接口的 limitations[2] 即此警告。

/**
 * Limitations documentation returned to the client for transparency.
 * Routes layer passes this through to the response body so the frontend
 * can honestly display them next to the action.
 */
export const REDEEM_SPLIT_LIMITATIONS = [
  '这不是真正的 Chaum 找零——银行把大额 token 全额退到账户，用户需另走 4-move 取款获得新面额 token。',
  'spent_coins 按 split_denomination 记账仅是教学展示，不改变 Chaum 协议语义；生产系统找零需商户侧协议（如 Brands 1993 钱包观察者方案）。',
  '银行可观察「大额兑付 + 后续小额取款」模式，存在时间侧信道——攻击者可借此缩小匿名集（参考 Chaum 1985）。',
];

/**
 * Redeem a large-denomination token by crediting the full amount to the
 * user's balance and recording the spend under the requested split
 * denomination (teaching-only: does NOT issue new tokens).
 *
 * @param {{
 *   user_id:number,
 *   serial:string, amount:number, R_prime:string, s_prime:string, key_id?:number,
 *   split_denomination:number,
 * }} args
 * @returns {{deposited:number, new_balance:number, split_denomination:number, split_count:number, limitations:string[]}}
 * @throws {PaymentError} 400 MALFORMED_TOKEN / 400 SIGNATURE_INVALID / 400 INVALID_SPLIT_DENOMINATION /
 *         400 SPLIT_NOT_DIVISIBLE / 409 DOUBLE_SPEND
 */
export function redeemSplit({ user_id, serial, amount, R_prime, s_prime, key_id, split_denomination }) {
  // 1. Validate split_denomination ∈ DENOMINATIONS
  if (!Number.isInteger(split_denomination) || !DENOMINATIONS.includes(split_denomination)) {
    throw new PaymentError(400, 'INVALID_SPLIT_DENOMINATION',
      `split_denomination must be one of ${DENOMINATIONS.join(', ')}`);
  }

  // 2. Format gate (H1: reject malformed before curve operations)
  const { serialBytes, RPrimeBytes, sPrimeBytes, sPrime } = formatGate({
    serial,
    amount,
    R_prime,
    s_prime,
  });

  // 3. Verify signature (OUTSIDE transaction — read-only curve math)
  let publicKey;
  try {
    publicKey = (key_id != null)
      ? getPublicKeyByVersion(key_id)
      : getActivePublicKey();
  } catch (e) {
    if (e instanceof BankKeyError) {
      throw new PaymentError(e.status, e.code, e.message);
    }
    throw e;
  }
  const ok = verifySig(RPrimeBytes, sPrime, serialBytes, amount, publicKey);
  if (!ok) {
    throw new PaymentError(400, 'SIGNATURE_INVALID',
      'signature verification failed — token is forged or tampered');
  }

  // 4. Split divisibility check (teaching: amount must be a multiple of
  //    split_denomination so the conceptual "split into N small coins" is
  //    well-formed; otherwise the requested split is meaningless).
  if (amount % split_denomination !== 0) {
    throw new PaymentError(400, 'SPLIT_NOT_DIVISIBLE',
      `amount (${amount}) must be divisible by split_denomination (${split_denomination})`);
  }
  const splitCount = amount / split_denomination;

  // 5. token_hash (H2: bytes-level concat to prevent casing ambiguity)
  const tokenHash = computeTokenHash(serialBytes, RPrimeBytes, sPrimeBytes);

  // 6. Atomic deposit (BEGIN IMMEDIATE holds the write lock).
  return runInvariantCheckedTx((db) => {
    // Primary double-spend guard
    const existing = db.prepare(
      `SELECT 1 FROM spent_coins WHERE serial = ?`,
    ).get(Buffer.from(serialBytes));
    if (existing) {
      throw new PaymentError(409, 'DOUBLE_SPEND',
        'this token has already been spent');
    }

    // Phase 6.2 教学化：INSERT spent_coins 时 denomination 列用
    // split_denomination 而非原 key_id 反查的 denom——直观展示"这笔兑付
    // 等价于 split_count 枚小币"。key_version 仍按原 token 的 key_id 记录
    // （用于 6.3 匿名集分析按 (denom, key_version) 分组统计）。
    const keyVersion = (key_id != null) ? key_id : getActiveKeyVersion();

    try {
      db.prepare(
        `INSERT INTO spent_coins (serial, amount, deposited_to, token_hash, key_version, denomination)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(
        Buffer.from(serialBytes),
        amount,
        user_id,
        Buffer.from(tokenHash),
        keyVersion,
        split_denomination,  // ← 教学化：用 split_denomination 而非原 denom
      );
    } catch (e) {
      if (e.message && e.message.includes('UNIQUE')) {
        throw new PaymentError(409, 'DOUBLE_SPEND',
          "token_hash collision — same (R', s') already spent under a different serial");
      }
      throw e;
    }

    // Credit user balance (全额退到账户)
    db.prepare(
      `UPDATE users SET balance = balance + ? WHERE id = ?`,
    ).run(amount, user_id);

    // Record transaction flow (kind='redeem_split' so /history distinguishes
    // this from normal 'deposit' / 'refund' / 'withdraw')
    recordTransaction(db, {
      user_id,
      kind: 'redeem_split',
      amount,
      counterparty: 'bank',
      serial: serialBytes,
      session_id: null,
      note: `split into ${splitCount}×${split_denomination}BC`,
    });

    // bank_reserve.total_redeemed += amount（与 /redeem 一致：token 兑付
    // 后退出流通，total_redeemed 记录所有兑付总量）
    db.prepare(
      `UPDATE bank_reserve
          SET total_redeemed = total_redeemed + ?,
              updated_at = CURRENT_TIMESTAMP
        WHERE id = 1`
    ).run(amount);

    // Audit log inside tx
    logAction({
      actor_id: user_id,
      action: 'redeem_split',
      amount,
      target: Buffer.from(serialBytes).toString('hex').slice(0, 16) + '...',
      meta: JSON.stringify({ key_version: keyVersion, split_denomination, split_count: splitCount }),
      db,
    });

    // assertInvariant 在事务内——失败整体回滚
    assertInvariant(db);

    const row = db.prepare(
      `SELECT balance FROM users WHERE id = ?`,
    ).get(user_id);
    if (!row) {
      throw new PaymentError(500, 'USER_NOT_FOUND', 'user account vanished mid-transaction');
    }

    return {
      deposited: amount,
      new_balance: row.balance,
      split_denomination,
      split_count: splitCount,
      limitations: REDEEM_SPLIT_LIMITATIONS,
    };
  });
}
