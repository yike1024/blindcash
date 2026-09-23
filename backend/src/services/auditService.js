// services/auditService.js — Phase 3: 审计日志
//
// v5 §三 3.3 落地：audit_log 表记录所有关键操作。
//   action ∈ {'key_rotate','deposit','withdraw','redeem','payment',
//              'invariant_violation','cancel','expire'}
//
// 调用约定：
//   - 成功路径的操作（deposit/withdraw/payment/key_rotate）在调用方
//     事务内写审计日志（logAction 传 db 参数）——事务提交则日志留存，
//     事务回滚则日志消失（符合"只记录成功操作"语义）。
//   - invariant_violation 是失败路径，事务已回滚——logAction 不传 db，
//     在事务外用自己的隐式事务写入（runInvariantCheckedTx catch 块）。
//
// N1 死锁修正落地：Phase 1 用 logger.error/logger.info 兜底，Phase 3
// 升级为 auditService.logAction。

import { getDb } from '../models/db.js';

/**
 * Write an audit log entry.
 *
 * @param {object} args
 * @param {number|null} [args.actor_id] — 操作发起者 user id（系统操作为 null）
 * @param {string} args.action — 操作类型
 * @param {string|null} [args.target] — 操作目标（session_id / serial hex / key_version）
 * @param {number|null} [args.amount] — 涉及金额
 * @param {string|null} [args.meta] — JSON 字符串附加上下文
 * @param {string|null} [args.ip] — 请求来源 IP
 * @param {import('better-sqlite3').Database} [args.db] — 调用方事务的 db 句柄
 *        （不传则用 getDb() 在独立隐式事务中写入）
 */
export function logAction({ actor_id, action, target, amount, meta, ip, db }) {
  const conn = db ?? getDb();
  conn.prepare(
    `INSERT INTO audit_log (actor_id, action, target, amount, meta, ip_address)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(
    actor_id ?? null,
    action,
    target ?? null,
    amount ?? null,
    meta ?? null,
    ip ?? null,
  );
}

/**
 * Query audit log entries with pagination (admin only).
 *
 * @param {object} opts
 * @param {number} [opts.page=1] — 1-based page number
 * @param {number} [opts.pageSize=20] — entries per page
 * @param {string} [opts.action] — filter by action type (optional)
 * @returns {{entries: Array, total: number, page: number, pageSize: number}}
 */
export function queryAuditLog({ page = 1, pageSize = 20, action } = {}) {
  const db = getDb();
  const offset = (page - 1) * pageSize;

  const where = action ? `WHERE action = ?` : '';
  const params = action ? [action, pageSize, offset] : [pageSize, offset];

  const entries = db.prepare(
    `SELECT id, actor_id, action, target, amount, meta, ip_address, created_at
     FROM audit_log ${where}
     ORDER BY created_at DESC, id DESC
     LIMIT ? OFFSET ?`,
  ).all(...params);

  const countSql = action
    ? `SELECT COUNT(*) AS cnt FROM audit_log WHERE action = ?`
    : `SELECT COUNT(*) AS cnt FROM audit_log`;
  const countParams = action ? [action] : [];
  const total = db.prepare(countSql).get(...countParams).cnt;

  return { entries, total, page, pageSize };
}
