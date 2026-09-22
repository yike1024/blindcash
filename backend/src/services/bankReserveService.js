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
// N1 修正：audit_log Phase 3 才建，Phase 1 用 logger.error 兜底。
// Phase 3 建好 audit_log 后，把 logger.error 改写为
// auditService.logAction({action:'invariant_violation', ...})，并加测试。
//
// 调用约定：assertInvariant 在调用方事务内调用（不是自己开事务），
// 这样失败时调用方的 BEGIN IMMEDIATE 整体回滚，不会出现"reserve 变了
// 但 SUM(balance) 没变"的半状态。

import { logger } from '../utils/logger.js';

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
    // N1 修正：audit_log Phase 3 才建，Phase 1 用 logger.error 兜底
    // Phase 3 建好 audit_log 后改写为 auditService.logAction({
    //   action: 'invariant_violation',
    //   reserve: r.reserve_balance, expected, sumBalance,
    //   total_issued: r.total_issued, total_redeemed: r.total_redeemed, inFlight,
    // })
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
