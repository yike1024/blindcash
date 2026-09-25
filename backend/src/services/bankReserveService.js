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
// 这样失败时调用方的 runImmediateTx 整体回滚，不会出现"reserve 变了
// 但 SUM(balance) 没变"的半状态。

import { runImmediateTx } from '../models/db.js';
import { logger } from '../utils/logger.js';
import { logAction } from './auditService.js';

export class ReserveInvariantError extends Error {
  constructor(message, details) {
    super(message);
    this.name = 'ReserveInvariantError';
    this.details = details;
  }
}

/**
 * Assert the bank_reserve invariant holds. MUST be called inside the caller's
 * transaction (runImmediateTx) so failure rolls back the entire write.
 *
 * Invariant (Phase 7 扩展):
 *   reserve_balance == SUM(users.balance)
 *                    + (total_issued − total_redeemed)
 *                    + SUM(amount WHERE withdrawal_sessions.status
 *                           IN ('pending','submitted'))
 *
 * 其中 (total_issued − total_redeemed) 已天然涵盖：
 *   - 自由流通 token（未花费）
 *   - locked 状态的在途托管资金（spent_coins 已占位，token 仍在 total_issued 中）
 *   故 payment_escrows 无需额外累加；confirm 时 total_redeemed 增加、
 *   locked 减少，cancel 时 locked 减少、sumBalance 增加，均守恒。
 *
 * @param {object} db — must be inside a tx
 */
export async function assertInvariant(db) {
  const r = await db.prepare(
    `SELECT reserve_balance, total_issued, total_redeemed
     FROM bank_reserve WHERE id = 1`
  ).get();

  if (!r) {
    logger.error({ msg: 'bank_reserve singleton row missing' });
    throw new ReserveInvariantError('bank_reserve singleton row missing');
  }

  const sumBalance = (await db.prepare(
    `SELECT COALESCE(SUM(balance), 0) AS s FROM users`
  ).get()).s;

  const inFlightWithdrawals = (await db.prepare(
    `SELECT COALESCE(SUM(amount), 0) AS s
     FROM withdrawal_sessions
     WHERE status IN ('pending','submitted')`
  ).get()).s;

  const expected = sumBalance + (r.total_issued - r.total_redeemed) + inFlightWithdrawals;

  if (r.reserve_balance !== expected) {
    logger.error({
      msg: 'reserve invariant violated',
      reserve: r.reserve_balance,
      expected,
      sumBalance,
      total_issued: r.total_issued,
      total_redeemed: r.total_redeemed,
      inFlightWithdrawals,
    });
    throw new ReserveInvariantError(
      `reserve=${r.reserve_balance} ≠ expected=${expected}`,
      {
        reserve: r.reserve_balance,
        expected,
        sumBalance,
        total_issued: r.total_issued,
        total_redeemed: r.total_redeemed,
        inFlightWithdrawals,
      },
    );
  }
}

/**
 * Run a transaction with invariant checking + audit logging on failure.
 * @param {(db: object) => Promise<any>} fn
 * @returns {Promise<any>}
 */
export async function runInvariantCheckedTx(fn) {
  try {
    return await runImmediateTx(fn);
  } catch (e) {
    if (e instanceof ReserveInvariantError) {
      await logAction({
        action: 'invariant_violation',
        meta: JSON.stringify(e.details ?? {}),
      });
    }
    throw e;
  }
}

/**
 * Ensure the bank_reserve singleton row exists.
 * @param {object} db
 */
export async function ensureSingletonRow(db) {
  await db.prepare(
    `INSERT INTO bank_reserve (id) VALUES (1) ON CONFLICT (id) DO NOTHING`
  ).run();
}
