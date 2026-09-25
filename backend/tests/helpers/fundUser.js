// tests/helpers/fundUser.js — Phase 1: proper test funding via deposit
//
// v5 §三 1.5 开户改革：新用户 balance=0，必须通过 deposit 充值才能取款。
// 直接 SQL 写 balance 会绕过 bank_reserve 更新，导致 assertInvariant 失败。
// fundUser 调用 bankService.deposit，同步更新：
//   users.balance += amount
//   bank_reserve.reserve_balance += amount
//   transactions 多一条 deposit 流水
//   assertInvariant 通过
//
// 用法：fundUser(userId, 100) → 在 beforeEach 或 beforeAll 中给用户充值

import { deposit } from '../../src/services/bankService.js';

/**
 * Fund a user's balance via the deposit service (simulated fiat rail).
 * Properly updates bank_reserve + assertInvariant — safe to use before
 * any withdrawal/payment operation that checks the invariant.
 *
 * @param {number} userId
 * @param {number} amount
 * @returns {{deposited:number, new_balance:number}}
 */
export function fundUser(userId, amount) {
  return deposit({ user_id: userId, amount, ip: '127.0.0.1' });
}

/**
 * Reset all balances + bank_reserve to zero state for beforeEach.
 * Clears: users.balance=0, bank_reserve singleton=0, protocol tables.
 * Call this in beforeEach BEFORE fundUser to ensure clean state.
 *
 * @param {object} db — db/tx wrapper from src/models/db.js
 */
export async function resetBalancesAndReserve(db) {
  await db.exec('DELETE FROM withdrawal_sessions;');
  await db.exec('DELETE FROM spent_coins;');
  await db.exec('DELETE FROM transactions;');
  // Reset all user balances to 0
  await db.exec('UPDATE users SET balance = 0;');
  // Reset bank_reserve singleton to 0 (Phase 1 clean state)
  await db.exec(
    `UPDATE bank_reserve SET total_issued = 0, total_redeemed = 0, reserve_balance = 0, updated_at = CURRENT_TIMESTAMP WHERE id = 1;`,
  );
}
