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

export const MAX_DEPOSIT_PER_TX = 1000;
export const MAX_DEPOSIT_PER_DAY = 5000;

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
 * @returns {Promise<{deposited:number, new_balance:number, daily_total:number}>}
 */
export async function deposit({ user_id, amount, ip }) {
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new BankServiceError(400, 'INVALID_AMOUNT',
      'amount must be a positive integer');
  }
  if (amount > MAX_DEPOSIT_PER_TX) {
    throw new BankServiceError(400, 'DEPOSIT_LIMIT_EXCEEDED',
      `single deposit cap is ${MAX_DEPOSIT_PER_TX} BC`);
  }

  // Rolling 24h window (PG: NOW() - INTERVAL '1 day')
  const dailyRow = await queryOne(
    `SELECT COALESCE(SUM(amount), 0) AS s
       FROM transactions
      WHERE user_id = ?
        AND kind = 'deposit'
        AND created_at >= NOW() - INTERVAL '1 day'`,
    [user_id],
  );
  const dailyTotal = dailyRow?.s ?? 0;
  if (dailyTotal + amount > MAX_DEPOSIT_PER_DAY) {
    throw new BankServiceError(400, 'DAILY_LIMIT_EXCEEDED',
      `24h rolling cap is ${MAX_DEPOSIT_PER_DAY} BC (current: ${dailyTotal})`);
  }

  return runInvariantCheckedTx(async (db) => {
    const updated = await db.prepare(
      `UPDATE users SET balance = balance + ? WHERE id = ?`
    ).run(amount, user_id);
    if (updated.changes !== 1) {
      throw new BankServiceError(404, 'USER_NOT_FOUND', 'user account not found');
    }

    await db.prepare(
      `UPDATE bank_reserve
          SET reserve_balance = reserve_balance + ?,
              updated_at = CURRENT_TIMESTAMP
        WHERE id = 1`
    ).run(amount);

    await recordTransaction(db, {
      user_id,
      kind: 'deposit',
      amount,
      counterparty: 'bank',
      note: 'simulated fiat rail',
    });

    await logAction({
      actor_id: user_id,
      action: 'deposit',
      amount,
      ip: ip ?? null,
      db,
    });

    await assertInvariant(db);

    const row = await db.prepare(
      `SELECT balance FROM users WHERE id = ?`
    ).get(user_id);

    return {
      deposited: amount,
      new_balance: row.balance,
      daily_total: dailyTotal + amount,
    };
  });
}
