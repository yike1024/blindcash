// services/sessionCleanupService.js — Phase 1 缺陷修复：方案 A 后台清理 job
//
// v5 §三 1.1 M1 惰性清理挂账场景处理（方案 A）：
//   后台清理 job 每小时扫一次全局过期会话 → refundAndClose → 在途项归零。
//
// 为什么需要：lazyCleanupExpiredSessions 只在"当前用户下次操作"时触发
// 清理。如果用户取款到一半关闭浏览器永不回来，pending/submitted 会话
// 永远挂在在途项里——reserve_balance 永远压着一笔"已扣款未签发"的钱。
// 后台 job 全局扫描兜底，保证挂账不会永久存在。
//
// 与 lazyCleanupExpiredSessions 的分工（v5 checklist #9）：
//   - lazyCleanupExpiredSessions：处理"当前用户"的过期会话（用户主动
//     操作路径，initWithdrawal 开头调用）
//   - startCleanupJob：全局扫描所有用户的过期会话（后台兜底，1h 一次）
//
// 调用约定：在 runMigrations 返回后 start，进程退出前 clearInterval。
// 使用 handle.unref() 使 setInterval 不阻止进程退出（测试/脚本场景）。

import { refundAndClose } from './withdrawalService.js';
import { runInvariantCheckedTx } from './bankReserveService.js';
import { logger } from '../utils/logger.js';

/**
 * Cleanup interval in milliseconds. Default 1 hour.
 * Overridable via BC_CLEANUP_INTERVAL_MS for tests / staging.
 */
const CLEANUP_INTERVAL_MS = parseInt(
  process.env.BC_CLEANUP_INTERVAL_MS ?? (60 * 60 * 1000),
  10,
);

/**
 * Run one global cleanup sweep: find ALL expired sessions across all users
 * and refund+close them. Reuses refundAndClose (which already calls
 * assertInvariant) so the invariant holds after the sweep.
 *
 * Safe to call directly (e.g., in tests) — returns the count of sessions
 * cleaned.
 *
 * @returns {number} count of sessions refunded+closed
 */
export function runGlobalCleanup() {
  return runInvariantCheckedTx((db) => {
    const now = new Date().toISOString();
    const expired = db.prepare(
      `SELECT id, customer_id, amount FROM withdrawal_sessions
       WHERE status IN ('pending','submitted') AND expires_at <= ?`,
    ).all(now);

    for (const s of expired) {
      refundAndClose(db, s, 'expired');
    }

    if (expired.length > 0) {
      logger.info({
        action: 'global_cleanup',
        cleaned: expired.length,
        at: now,
      });
    }
    return expired.length;
  });
}

/**
 * Start the periodic cleanup job. Returns a stop() function that clears
 * the interval. Call this in initDatabase() after runMigrations().
 *
 * handle.unref() ensures the interval timer does NOT keep the Node event
 * loop alive — without it, test processes and CLI scripts would hang forever
 * waiting for the timer to fire.
 *
 * @returns {() => void} stop function
 */
export function startCleanupJob() {
  const handle = setInterval(() => {
    try {
      runGlobalCleanup();
    } catch (err) {
      // Swallow errors inside the timer — a cleanup failure must NOT crash
      // the server. Log it and let the next tick retry.
      logger.error({ action: 'global_cleanup_failed', error: err.message });
    }
  }, CLEANUP_INTERVAL_MS);

  // Do not prevent process exit. Without this, `npm test` and CLI scripts
  // would hang waiting for the 1h interval.
  if (typeof handle.unref === 'function') {
    handle.unref();
  }

  logger.info({
    action: 'cleanup_job_started',
    interval_ms: CLEANUP_INTERVAL_MS,
  });

  return () => {
    clearInterval(handle);
    logger.info({ action: 'cleanup_job_stopped' });
  };
}
