// services/sessionCleanupService.js — 后台清理 job (PostgreSQL async)

import { refundAndClose } from './withdrawalService.js';
import { runInvariantCheckedTx } from './bankReserveService.js';
import { logger } from '../utils/logger.js';

const CLEANUP_INTERVAL_MS = parseInt(
  process.env.BC_CLEANUP_INTERVAL_MS ?? (60 * 60 * 1000),
  10,
);

/**
 * Run one global cleanup sweep.
 * @returns {Promise<number>} count of sessions refunded+closed
 */
export async function runGlobalCleanup() {
  return runInvariantCheckedTx(async (db) => {
    const expired = await db.prepare(
      `SELECT id, customer_id, amount FROM withdrawal_sessions
       WHERE status IN ('pending','submitted') AND expires_at < CURRENT_TIMESTAMP`,
    ).all();

    for (const s of expired) {
      await refundAndClose(db, s, 'expired');
    }

    if (expired.length > 0) {
      logger.info({
        action: 'global_cleanup',
        cleaned: expired.length,
      });
    }
    return expired.length;
  });
}

export function startCleanupJob() {
  const handle = setInterval(() => {
    runGlobalCleanup().catch((err) => {
      logger.error({ action: 'global_cleanup_failed', error: err.message });
    });
  }, CLEANUP_INTERVAL_MS);

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
