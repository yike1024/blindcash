// services/bankService.js — Phase 1: 银行充值（simulated fiat rail）
//
// v5 §三 1.2 落地：POST /api/bank/deposit 让用户自助充值 BC，模拟外部
// 法币入账。这是新货币经济学闭环的入口——新用户 balance=0，必须
// 充值才能取款，不再教学性赠送 100 BC。
//
// 充值限额：
//   MAX_DEPOSIT_PER_TX  = 1000  （单次上限）
//   MAX_DEPOSIT_PER_DAY  = 5000  （日累计上限，m3 修正防脚本循环充值刷量）
//
// **N1 修正**：日累计查 `transactions WHERE kind='deposit' AND user_id=?
//   AND created_at >= datetime('now','-1 day')`——不用 audit_log
//   （Phase 3 才建），transactions 本来就是用户可见流水，语义自洽。
//
// **P3b 修正**：用 `datetime('now','-1 day')` 滚动 24h 窗口而非
//   `date('now')` UTC 零点——北京时间 8 点前充值会被算成"昨天"导致
//   边界用例撞墙；24h 滚动窗口语义更直觉。
//
// **N4 + M3 修正**：service 层不碰 crypto 层的 verifySig，只负责 balance
// 变更 + 写流水 + assertInvariant。crypto 层签名不变。
//
// 所有 balance 变更在 runImmediateTx 内原子执行：
//   UPDATE users.balance += amount
//   UPDATE bank_reserve.reserve_balance += amount
//   recordTransaction(kind='deposit', counterparty='bank')
//   assertInvariant(db)  — 失败回滚整个事务

import { queryOne } from '../models/db.js';
import { recordTransaction } from './transactionService.js';
import { assertInvariant, runInvariantCheckedTx } from './bankReserveService.js';
import { logAction } from './auditService.js';

/**
 * Single-deposit cap (BC units). Deposits above this are rejected with 400.
 */
export const MAX_DEPOSIT_PER_TX = 1000;

/**
 * Rolling 24-hour deposit cap per user. Deposits that would push the user's
 * 24h total above this are rejected with 400.
 */
export const MAX_DEPOSIT_PER_DAY = 5000;

/**
 * Error carrying an HTTP status. Routes catch this and map to res.status().
 */
export class BankServiceError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'BankServiceError';
    this.status = status;
    this.code = code;
  }
}

/**
 * Deposit BC into a user's account (simulated external fiat rail).
 *
 * Flow:
 *   1. Validate amount is a positive integer ≤ MAX_DEPOSIT_PER_TX
 *   2. Check 24h rolling sum from transactions (P3b: not audit_log)
 *   3. runImmediateTx:
 *        UPDATE users.balance += amount
 *        UPDATE bank_reserve.reserve_balance += amount
 *        recordTransaction(kind='deposit', counterparty='bank')
 *        assertInvariant(db)  — fails → rollback whole tx
 *
 * @param {{user_id:number, amount:number, ip?:string}} args
 * @returns {{deposited:number, new_balance:number, daily_total:number}}
 * @throws {BankServiceError} 400 INVALID_AMOUNT / 400 DEPOSIT_LIMIT_EXCEEDED /
 *         400 DAILY_LIMIT_EXCEEDED
 */
export function deposit({ user_id, amount, ip }) {
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new BankServiceError(400, 'INVALID_AMOUNT',
      'amount must be a positive integer');
  }
  if (amount > MAX_DEPOSIT_PER_TX) {
    throw new BankServiceError(400, 'DEPOSIT_LIMIT_EXCEEDED',
      `single deposit cap is ${MAX_DEPOSIT_PER_TX} BC`);
  }

  // P3b: datetime('now','-1 day') 滚动 24h 窗口（UTC 零点会让 8 点前
  // 充值算成"昨天"撞边界）
  const dailyRow = queryOne(
    `SELECT COALESCE(SUM(amount), 0) AS s
       FROM transactions
      WHERE user_id = ?
        AND kind = 'deposit'
        AND created_at >= datetime('now','-1 day')`,
    [user_id],
  );
  const dailyTotal = dailyRow?.s ?? 0;
  if (dailyTotal + amount > MAX_DEPOSIT_PER_DAY) {
    throw new BankServiceError(400, 'DAILY_LIMIT_EXCEEDED',
      `24h rolling cap is ${MAX_DEPOSIT_PER_DAY} BC (current: ${dailyTotal})`);
  }

  // runInvariantCheckedTx: 所有 balance 变更原子化，失败 assertInvariant 回滚
  // + 在 catch 块中写 invariant_violation 审计日志
  return runInvariantCheckedTx((db) => {
    const updated = db.prepare(
      `UPDATE users SET balance = balance + ? WHERE id = ?`
    ).run(amount, user_id);
    if (updated.changes !== 1) {
      throw new BankServiceError(404, 'USER_NOT_FOUND', 'user account not found');
    }

    db.prepare(
      `UPDATE bank_reserve
          SET reserve_balance = reserve_balance + ?,
              updated_at = CURRENT_TIMESTAMP
        WHERE id = 1`
    ).run(amount);

    recordTransaction(db, {
      user_id,
      kind: 'deposit',
      amount,
      counterparty: 'bank',
      note: 'simulated fiat rail',
    });

    // Phase 3 (N1 落地)：deposit 审计日志写在事务内（事务提交则留存）
    logAction({
      actor_id: user_id,
      action: 'deposit',
      amount,
      ip: ip ?? null,
      db,
    });

    // assertInvariant 在事务内调用——失败时整个 BEGIN IMMEDIATE 回滚
    // 不会出现 balance 变了但 reserve_balance 没变的半状态
    assertInvariant(db);

    const row = db.prepare(
      `SELECT balance FROM users WHERE id = ?`
    ).get(user_id);

    return {
      deposited: amount,
      new_balance: row.balance,
      daily_total: dailyTotal + amount,
    };
  });
}
