// services/withdrawalService.js — M4: 4-move withdrawal protocol state machine
//
// v3 §2.3 cut-and-choose 4-move protocol, bank side:
//   ① init    — lazy-cleanup, debit, generate N k_i, store session(pending)
//   ③ submit  — pick j, store blinded candidates (NO α/β), status=submitted
//   ⑤ reveal — verify all i≠j, sign s_j=k_j+e_j·x, status=committed
//   ⑦ cancel — refund, status=cancelled
//
// ISOLATION.md hard invariants enforced here:
//   §三-3 (blindness):   candidates JSON stores {k,R,e,R_prime,serial,status}
//                        but NEVER α_i/β_i. submit/reveal APIs 400 any payload
//                        that carries α/β for the wrong index.
//   §三-4 (active-1):     at most one pending|submitted session per customer.
//                        Service-layer check + DB partial UNIQUE index = 409.
//   §三-5 (nonce-fresh):  N fresh k_i generated per init, never reused.
//   §一-1 (balance):     init debits, cancel/expire/abort refund customer.balance.
//
// All balance mutations run inside runImmediateTx so the write lock is held
// for the full check+update — no TOCTOU window for double-debit / double-refund.

import { randomUUID } from 'node:crypto';
import { queryOne, runWrite, runImmediateTx } from '../models/db.js';
import { getPublicKey, getPrivateKey } from './bankKeyService.js';
import { bankStep1, bankStep3 } from '../crypto/server/schnorrBlind.js';
import { verifyRevealed, pickRandomJ } from '../crypto/server/cutAndChoose.js';
import { randomScalar, scalarToBytes, bytesToScalar, isValidScalar } from '../crypto/server/curve.js';
import { bytesToHex, hexToBytes } from '../utils/hex.js';
import { CUT_AND_CHOOSE_N, SESSION_TTL_MS } from '../config/bank.js';

/**
 * Error carrying an HTTP status. Routes catch this and map to res.status().
 * Anything thrown that isn't a WithdrawalError is treated as 500.
 */
export class WithdrawalError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'WithdrawalError';
    this.status = status;
    this.code = code;
  }
}

// ── bigint ↔ hex helpers (k/e/alpha/beta are bigints; JSON can't store them) ──
function scalarToHex(s) {
  return bytesToHex(scalarToBytes(s));
}
function hexToScalar(hex) {
  return bytesToScalar(hexToBytes(hex));
}

// ── candidate record shape (what we persist) ──
// init produces:  { k, R, status:'pending' }
// submit extends: { k, R, e, R_prime, serial, status:'submitted' }
// NEVER stores alpha/beta — ISOLATION §三-3.

/**
 * Refund a session's amount back to its owner and flip status.
 * MUST run inside an open transaction (caller's runImmediateTx).
 * @param {import('better-sqlite3').Database} db
 * @param {{id:string, customer_id:number, amount:number}} session
 * @param {'aborted'|'cancelled'|'expired'} newStatus
 */
function refundAndClose(db, session, newStatus) {
  db.prepare(`UPDATE users SET balance = balance + ? WHERE id = ?`)
    .run(session.amount, session.customer_id);
  db.prepare(`UPDATE withdrawal_sessions SET status = ? WHERE id = ?`)
    .run(newStatus, session.id);
}

/**
 * Lazily refund + expire any of this customer's sessions past their TTL.
 * Runs in its own BEGIN IMMEDIATE so it cannot race with the init that
 * follows. Called at the top of initWithdrawal (v3 §2.3 step ①).
 *
 * ISOLATION §一-1: refund credits customer.balance (the inverse of init's debit).
 *
 * @param {number} customerId
 * @returns {number} count of sessions expired
 */
export function lazyCleanupExpiredSessions(customerId) {
  return runImmediateTx((db) => {
    const now = new Date().toISOString();
    const expired = db.prepare(
      `SELECT id, customer_id, amount FROM withdrawal_sessions
       WHERE customer_id = ? AND status IN ('pending','submitted') AND expires_at <= ?`,
    ).all(customerId, now);
    for (const s of expired) {
      refundAndClose(db, s, 'expired');
    }
    return expired.length;
  });
}

/**
 * ① POST /withdraw/init — open a new withdrawal session.
 *
 * Flow:
 *   1. lazyCleanupExpiredSessions (refund the customer's expired sessions)
 *   2. BEGIN IMMEDIATE:
 *      - reject if a pending|submitted session still exists (409, 不变量 4)
 *      - reject if balance < amount (400)
 *      - debit balance
 *      - generate N fresh k_i (randomScalar — 不变量 5, never reused)
 *      - compute R_i = k_i·G (bankStep1)
 *      - INSERT session(pending, expires_at)
 *   3. return { session_id, R_1..R_N, amount, N }
 *
 * @param {{customer_id:number, amount:number}} args
 * @returns {{session_id:string, R:string[], amount:number, N:number}}
 */
export function initWithdrawal({ customer_id, amount }) {
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new WithdrawalError(400, 'INVALID_AMOUNT', 'amount must be a positive integer');
  }

  // ① lazy-cleanup this customer's expired sessions before considering a new one
  lazyCleanupExpiredSessions(customer_id);

  return runImmediateTx((db) => {
    // 不变量 4: at most one active session per customer
    const active = db.prepare(
      `SELECT id FROM withdrawal_sessions
       WHERE customer_id = ? AND status IN ('pending','submitted')`,
    ).get(customer_id);
    if (active) {
      throw new WithdrawalError(409, 'ACTIVE_SESSION_EXISTS',
        'you already have an active withdrawal session; finish or cancel it first');
    }

    // balance check + debit
    const user = db.prepare(`SELECT balance FROM users WHERE id = ?`).get(customer_id);
    if (!user) {
      throw new WithdrawalError(404, 'USER_NOT_FOUND', 'customer account not found');
    }
    if (user.balance < amount) {
      throw new WithdrawalError(400, 'INSUFFICIENT_BALANCE',
        `balance ${user.balance} < requested ${amount}`);
    }
    db.prepare(`UPDATE users SET balance = balance - ? WHERE id = ?`)
      .run(amount, customer_id);

    // 不变量 5: N fresh k_i per session, never reused
    const N = CUT_AND_CHOOSE_N;
    const candidates = [];
    const Rlist = [];
    for (let i = 0; i < N; i++) {
      const k = randomScalar();
      if (!isValidScalar(k)) throw new Error('init: generated invalid k (out of range)');
      const { RBytes } = bankStep1(k);
      candidates.push({ k: scalarToHex(k), R: bytesToHex(RBytes), status: 'pending' });
      Rlist.push(bytesToHex(RBytes));
    }

    const sessionId = randomUUID();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    db.prepare(
      `INSERT INTO withdrawal_sessions
         (id, customer_id, amount, n_candidates, candidates, status, expires_at)
       VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
    ).run(sessionId, customer_id, amount, N, JSON.stringify(candidates), expiresAt);

    return { session_id: sessionId, R: Rlist, amount, N };
  });
}

/**
 * ③ POST /withdraw/submit — user submits N blinded candidates, bank picks j.
 *
 * API DEFENSE (不变量 3): if any candidate element contains `alpha` or `beta`
 * keys, we 400 immediately — α/β for the to-be-signed candidate must never
 * leave the user's device. This is the executable test surface for ISOLATION
 * §三-3 that the professor flagged as a must-test for M4.
 *
 * @param {{session_id:string, customer_id:number, candidates:Array}} args
 *   args.candidates: [{ e:hex, R_prime:hex, serial:hex }, ...] length N
 * @returns {{j:number}}
 */
export function submitCandidates({ session_id, customer_id, candidates }) {
  // ── API defense: α/β must never be submitted ── (不变量 3, 教授必测 #1)
  if (!Array.isArray(candidates)) {
    throw new WithdrawalError(400, 'INVALID_CANDIDATES', 'candidates must be an array');
  }
  for (const c of candidates) {
    if (c === null || typeof c !== 'object') {
      throw new WithdrawalError(400, 'INVALID_CANDIDATE', 'each candidate must be an object');
    }
    if ('alpha' in c || 'beta' in c) {
      throw new WithdrawalError(400, 'BLINDER_LEAKED',
        'submit payload must not contain alpha/beta — blinders never leave the user device');
    }
    if (typeof c.e !== 'string' || typeof c.R_prime !== 'string' || typeof c.serial !== 'string') {
      throw new WithdrawalError(400, 'INVALID_CANDIDATE',
        'each candidate requires {e, R_prime, serial} as hex strings');
    }
  }

  // ⚠退款必须在事务内正常提交（不能 throw 导致回滚）：用 result 对象携带
  // error 出事务，在事务外 throw，这样退款 UPDATE 持久化，错误仍正确传播。
  const result = runImmediateTx((db) => {
    const session = db.prepare(
      `SELECT * FROM withdrawal_sessions WHERE id = ? AND customer_id = ?`,
    ).get(session_id, customer_id);
    if (!session) {
      return { error: new WithdrawalError(404, 'SESSION_NOT_FOUND',
        'session does not exist or does not belong to you') };
    }
    if (session.status !== 'pending') {
      return { error: new WithdrawalError(409, 'WRONG_STATUS',
        `session is ${session.status}, must be pending to submit`) };
    }
    // expiry check — refund + flip to expired so the user can start a new one
    if (new Date(session.expires_at) <= new Date()) {
      refundAndClose(db, session, 'expired');
      return { error: new WithdrawalError(400, 'SESSION_EXPIRED',
        'session TTL elapsed; balance refunded, please re-init') };
    }
    if (candidates.length !== session.n_candidates) {
      return { error: new WithdrawalError(400, 'CANDIDATE_COUNT',
        `expected ${session.n_candidates} candidates, got ${candidates.length}`) };
    }

    // merge e/R_prime/serial into the stored candidates, pick j
    const stored = JSON.parse(session.candidates);
    for (let i = 0; i < candidates.length; i++) {
      stored[i].e = candidates[i].e;
      stored[i].R_prime = candidates[i].R_prime;
      stored[i].serial = candidates[i].serial;
      stored[i].status = 'submitted';
    }
    const j = pickRandomJ(session.n_candidates);

    db.prepare(
      `UPDATE withdrawal_sessions
         SET candidates = ?, j_index = ?, status = 'submitted'
       WHERE id = ?`,
    ).run(JSON.stringify(stored), j, session_id);

    return { j };
  });

  if (result.error) throw result.error;
  return result;
}

/**
 * ⑤ POST /withdraw/reveal — user reveals α_i, β_i for i ≠ j; bank verifies +
 * signs candidate j.
 *
 * API DEFENSE (不变量 3): if the revealed array contains an entry with i === j,
 * we 400 — revealing the signed candidate's blinders would let the bank link
 * (R_j, e_j) ↔ (R'_j, e'_j) and unblind the token. Professor-flagged must-test.
 *
 * Verify each i≠j via cutAndChoose.verifyRevealed; any failure → refund +
 * status='aborted' + 400. All pass → s_j = (k_j + e_j·x) mod n, status='committed'.
 *
 * @param {{session_id:string, customer_id:number, revealed:Array}} args
 *   args.revealed: [{ i:number, alpha:hex, beta:hex }, ...] length N-1, i ≠ j
 * @returns {{s_j:string}} hex of 32-byte s
 */
export function revealAndSign({ session_id, customer_id, revealed }) {
  if (!Array.isArray(revealed)) {
    throw new WithdrawalError(400, 'INVALID_REVEALED', 'revealed must be an array');
  }
  for (const r of revealed) {
    if (r === null || typeof r !== 'object') {
      throw new WithdrawalError(400, 'INVALID_REVEAL', 'each reveal must be an object');
    }
    if (typeof r.i !== 'number' || typeof r.alpha !== 'string' || typeof r.beta !== 'string') {
      throw new WithdrawalError(400, 'INVALID_REVEAL',
        'each reveal requires {i:number, alpha:hex, beta:hex}');
    }
  }

  // ⚠退款必须在事务内正常提交（不能 throw 导致回滚）：用 result 对象携带
  // error 出事务，在事务外 throw，这样退款/abort UPDATE 持久化，错误仍正确传播。
  const result = runImmediateTx((db) => {
    const session = db.prepare(
      `SELECT * FROM withdrawal_sessions WHERE id = ? AND customer_id = ?`,
    ).get(session_id, customer_id);
    if (!session) {
      return { error: new WithdrawalError(404, 'SESSION_NOT_FOUND',
        'session does not exist or does not belong to you') };
    }
    if (session.status !== 'submitted') {
      return { error: new WithdrawalError(409, 'WRONG_STATUS',
        `session is ${session.status}, must be submitted to reveal`) };
    }
    if (new Date(session.expires_at) <= new Date()) {
      refundAndClose(db, session, 'expired');
      return { error: new WithdrawalError(400, 'SESSION_EXPIRED',
        'session TTL elapsed; balance refunded') };
    }

    const j = session.j_index;
    // ── API defense: revealing i === j leaks the signed candidate's blinders ──
    for (const r of revealed) {
      if (r.i === j) {
        return { error: new WithdrawalError(400, 'SIGNED_CANDIDATE_REVEALED',
          'cannot reveal blinders for the signed candidate j — blindness would break') };
      }
    }
    // revealed set must be exactly {0..N-1} \ {j}
    const expectedCount = session.n_candidates - 1;
    if (revealed.length !== expectedCount) {
      return { error: new WithdrawalError(400, 'REVEAL_COUNT',
        `expected ${expectedCount} revealed (all i≠j), got ${revealed.length}`) };
    }
    const seenIdx = new Set(revealed.map((r) => r.i));
    if (seenIdx.size !== expectedCount) {
      return { error: new WithdrawalError(400, 'REVEAL_DUPLICATE', 'duplicate i in revealed array') };
    }
    for (let i = 0; i < session.n_candidates; i++) {
      if (i === j) continue;
      if (!seenIdx.has(i)) {
        return { error: new WithdrawalError(400, 'REVEAL_INCOMPLETE',
          `missing reveal for candidate i=${i}`) };
      }
    }

    const stored = JSON.parse(session.candidates);
    const publicKey = getPublicKey();

    // verify every i ≠ j
    for (const r of revealed) {
      const cand = stored[r.i];
      const ok = verifyRevealed({
        R: hexToBytes(cand.R),
        RPrime: hexToBytes(cand.R_prime),
        serial: hexToBytes(cand.serial),
        amount: session.amount,
        publicKey,
        alpha: hexToScalar(r.alpha),
        beta: hexToScalar(r.beta),
        e: hexToScalar(cand.e),
      });
      if (!ok) {
        // cut-and-choose failed → refund + abort (MUST commit, not rollback)
        refundAndClose(db, session, 'aborted');
        return { error: new WithdrawalError(400, 'CUT_AND_CHOOSE_FAILED',
          `verification failed for candidate i=${r.i}; session aborted and balance refunded`) };
      }
    }

    // all verified → sign candidate j: s_j = (k_j + e_j·x) mod n
    const candJ = stored[j];
    const kJ = hexToScalar(candJ.k);
    const eJ = hexToScalar(candJ.e);
    const x = bytesToScalar(getPrivateKey());
    const sJ = bankStep3(kJ, eJ, x);

    db.prepare(
      `UPDATE withdrawal_sessions SET status = 'committed' WHERE id = ?`,
    ).run(session_id);

    return { s_j: scalarToHex(sJ) };
  });

  if (result.error) throw result.error;
  return result;
}

/**
 * ⑦ POST /withdraw/cancel — user abandons a pending/submitted session; refund.
 *
 * @param {{session_id:string, customer_id:number}} args
 * @returns {{refunded:number, new_balance:number}}
 */
export function cancelWithdrawal({ session_id, customer_id }) {
  return runImmediateTx((db) => {
    const session = db.prepare(
      `SELECT * FROM withdrawal_sessions WHERE id = ? AND customer_id = ?`,
    ).get(session_id, customer_id);
    if (!session) {
      throw new WithdrawalError(404, 'SESSION_NOT_FOUND',
        'session does not exist or does not belong to you');
    }
    if (session.status !== 'pending' && session.status !== 'submitted') {
      throw new WithdrawalError(400, 'NOT_CANCELLABLE',
        `session is ${session.status}; only pending|submitted can be cancelled`);
    }
    refundAndClose(db, session, 'cancelled');
    const user = db.prepare(`SELECT balance FROM users WHERE id = ?`).get(customer_id);
    return { refunded: session.amount, new_balance: user.balance };
  });
}
