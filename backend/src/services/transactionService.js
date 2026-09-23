// services/transactionService.js — M7: 账本流水（transactions 表）
//
// 让取款去向可见：取款 / 收款 / 退款 各写一条流水，用户能在 /history 页
// 看到自己账户的完整资金流向。
//
// 设计要点：
//   * recordTransaction 必须在调用方事务内执行（传入 db 句柄），与 balance
//     变更原子——绝不能出现 balance 改了但流水没写、或流水写了但 balance
//     没改的分裂状态。
//   * listTransactions 是独立只读查询，走 getDb() 单例。
//   * kind 语义：
//       withdraw     — 用户向银行取款，balance 减少；
//       deposit      — 用户存入 token（商户收款），balance 增加；
//       refund       — 取款会话取消/过期/abort 后退款，balance 恢复；
//       redeem_split — Phase 6.2: 大额 token 按 split_denomination 退币到账户，
//                      balance 增加（与 deposit 类似，但独立 kind 以便
//                      /history 区分"找零兑付"与"商户收款"）。
//   * counterparty 对 withdraw/refund/redeem_split 为 'bank'；对 deposit 为 NULL
//     （Chaum 盲现的核心：token 匿名，商户无法知道付款人是谁）。

import { getDb } from '../models/db.js';

/**
 * 在调用方事务内写一条流水。MUST be called inside runImmediateTx((db) => ...).
 *
 * @param {import('better-sqlite3').Database} db        调用方事务的 db 句柄
 * @param {{user_id:number, kind:string, amount:number,
 *          counterparty?:string|null, serial?:Uint8Array|null,
 *          session_id?:string|null, note?:string}} args
 * @returns {number} insert row id
 */
export function recordTransaction(db, {
  user_id, kind, amount,
  counterparty = null, serial = null, session_id = null, note = null,
}) {
  if (!Number.isInteger(user_id) || user_id <= 0) {
    throw new Error('recordTransaction: user_id must be a positive integer');
  }
  if (!['withdraw', 'deposit', 'refund', 'redeem_split'].includes(kind)) {
    throw new Error(`recordTransaction: invalid kind '${kind}'`);
  }
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new Error('recordTransaction: amount must be a positive integer');
  }
  const serialBuf = serial ? Buffer.from(serial) : null;
  const result = db.prepare(
    `INSERT INTO transactions
       (user_id, kind, amount, counterparty, serial, session_id, note)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(user_id, kind, amount, counterparty, serialBuf, session_id, note);
  return Number(result.lastInsertRowid);
}

/**
 * 查询用户的账本流水（最新 limit 条，倒序）。
 * 独立只读查询，不在事务内。
 *
 * @param {number} userId
 * @param {number} [limit=50] 最多返回多少条
 * @returns {Array<{id:number, user_id:number, kind:string, amount:number,
 *           counterparty:string|null, serial:Uint8Array|null,
 *           session_id:string|null, note:string|null, created_at:string}>}
 */
export function listTransactions(userId, limit = 50) {
  if (!Number.isInteger(userId) || userId <= 0) {
    throw new Error('listTransactions: userId must be a positive integer');
  }
  const cap = Math.min(Math.max(1, Number(limit) || 50), 200);
  const db = getDb();
  const rows = db.prepare(
    `SELECT id, user_id, kind, amount, counterparty, serial, session_id, note, created_at
       FROM transactions
      WHERE user_id = ?
      ORDER BY created_at DESC, id DESC
      LIMIT ?`,
  ).all(userId, cap);
  // serial 列以 Buffer 形式回来，转成 Uint8Array 以保持一致性
  return rows.map((r) => ({
    ...r,
    serial: r.serial ? new Uint8Array(r.serial) : null,
  }));
}
