// services/bankReserveService.js — Phase 1: bank_reserve 不变量断言
//
// v5 §三 1.1 M1 修正后的核心不变量（含在途项）：
//   reserve_balance == SUM(users.balance)
//                    + (total_issued − total_redeemed)
//                    + SUM(amount WHERE withdrawal_sessions.status
//                           IN ('pending','submitted'))
//
// 所有涉及 balance/reserve 变更的操作（init/submit/reveal/cancel/expire/
// lazy-cleanup/deposit/redeem/payment）在 runImmediateTx 末尾调用
// assertInvariant(db)。失败抛 ReserveInvariantError → 调用方事务回滚。
//
// N1 修正落地：Phase 3 建好 audit_log 后，invariant_violation 写入
// audit_log。因为 invariant 违反发生在事务内（事务会回滚），所以
// runInvariantCheckedTx 在 catch 块中（事务外）写入审计日志。
//
// 调用约定：assertInvariant 在调用方事务内调用（不是自己开事务），
// 这样失败时调用方的 BEGIN IMMEDIATE 整体回滚，不会出现"reserve 变了
// 但 SUM(balance) 没变"的半状态。

import { runImmediateTx } from '../models/db.js';
import { logger } from '../utils/logger.js';
import { logAction } from './auditService.js';

/**
 * Error thrown when the reserve invariant is violated. Callers inside a
 * runImmediateTx will see this propagate up → transaction rollback.
 */
export class ReserveInvariantError extends Error {
  constructor(message, details) {
    super(message);
    this.name = 'ReserveInvariantError';
    this.details = details;  // { reserve, expected, sumBalance, ... }
  }
}

/**
 * Assert the bank_reserve invariant holds. MUST be called inside the caller's
 * transaction (runImmediateTx) so failure rolls back the entire write.
 *
 * Invariant (M1 修正后, 含在途项):
 *   reserve_balance == SUM(users.balance)
 *                    + (total_issued − total_redeemed)
 *                    + SUM(amount WHERE withdrawal_sessions.status
 *                           IN ('pending','submitted'))
 *
 * @param {import('better-sqlite3').Database} db — must be inside a tx
 * @throws {ReserveInvariantError} if invariant violated
 */
export function assertInvariant(db) {
  const r = db.prepare(
    `SELECT reserve_balance, total_issued, total_redeemed
     FROM bank_reserve WHERE id = 1`
  ).get();

  if (!r) {
    // bank_reserve singleton row missing — bank_reserve service not bootstrapped
    logger.error({ msg: 'bank_reserve singleton row missing' });
    throw new ReserveInvariantError('bank_reserve singleton row missing');
  }

  const sumBalance = db.prepare(
    `SELECT COALESCE(SUM(balance), 0) AS s FROM users`
  ).get().s;

  const inFlight = db.prepare(
    `SELECT COALESCE(SUM(amount), 0) AS s
     FROM withdrawal_sessions
     WHERE status IN ('pending','submitted')`
  ).get().s;

  const expected = sumBalance + (r.total_issued - r.total_redeemed) + inFlight;

  if (r.reserve_balance !== expected) {
    // Phase 3 (N1 落地)：invariant_violation 审计日志由
    // runInvariantCheckedTx 在事务回滚后的 catch 块中写入。
    // 这里仍用 logger.error 兜底（persists to stderr even if audit write fails）。
    logger.error({
      msg: 'reserve invariant violated',
      reserve: r.reserve_balance,
      expected,
      sumBalance,
      total_issued: r.total_issued,
      total_redeemed: r.total_redeemed,
      inFlight,
    });
    throw new ReserveInvariantError(
      `reserve=${r.reserve_balance} ≠ expected=${expected}`,
      {
        reserve: r.reserve_balance,
        expected,
        sumBalance,
        total_issued: r.total_issued,
        total_redeemed: r.total_redeemed,
        inFlight,
      },
    );
  }
}

/**
 * Run a transaction with invariant checking + audit logging on failure.
 *
 * Wraps runImmediateTx. If assertInvariant throws ReserveInvariantError
 * inside the tx, the tx rolls back, then this catch block writes an
 * 'invariant_violation' audit log entry OUTSIDE the (now-rolled-back) tx.
 *
 * Phase 3 (N1 落地): replaces bare runImmediateTx in services that call
 * assertInvariant (deposit, payment, withdrawal init/submit/reveal/cancel).
 *
 * @param {(db: import('better-sqlite3').Database) => any} fn
 * @returns {any} whatever fn returns on commit
 * @throws {ReserveInvariantError} if invariant violated (after audit log write)
 */
export function runInvariantCheckedTx(fn) {
  try {
    return runImmediateTx(fn);
  } catch (e) {
    if (e instanceof ReserveInvariantError) {
      logAction({
        action: 'invariant_violation',
        meta: JSON.stringify(e.details ?? {}),
      });
    }
    throw e;
  }
}

/**
 * Convenience: ensure the bank_reserve singleton row exists. Called on boot
 * after runMigrations (002_bank_reserve.sql INSERT OR IGNORE handles this,
 * but this helper is defensive — if someone deletes the row, the next
 * assertInvariant would fail with the "missing row" branch above).
 * @param {import('better-sqlite3').Database} db
 */
export function ensureSingletonRow(db) {
  db.prepare(
    `INSERT OR IGNORE INTO bank_reserve (id) VALUES (1)`
  ).run();
}
