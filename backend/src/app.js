// BlindCash backend entry — M1 + M3 + M4 + M5 + M7
//
// M1 scope: health check + auth routes (register/login with role).
// M3 scope: bank keypair provisioning on boot + GET /api/bank/pubkey.
// M4 scope: 4-move withdrawal protocol (init/submit/reveal/cancel).
// M5 scope: payment endpoint (POST /api/payment).
// M7 scope: transactions 账本表 + GET /api/transactions + 角色解锁闭环.

import express from 'express';
import cors from 'cors';
import { getDb, closeDb } from './models/db.js';
import { runMigrations } from './utils/migrationRunner.js';
import { getOrGenerate } from './services/bankKeyService.js';
import { startCleanupJob } from './services/sessionCleanupService.js';
import { bytesToHex } from './utils/hex.js';

import authRoutes from './routes/auth.js';
import bankRoutes from './routes/bank.js';
import withdrawalRoutes from './routes/withdrawal.js';
import paymentRoutes from './routes/payment.js';
import transactionsRoutes from './routes/transactions.js';

// NOTE: blindcash uses port 4100 (NOT 4000) so it can run side-by-side with
// the cryptobank project (which uses 4000). The Vite dev server runs on 5174
// (cryptobank uses 5173) and proxies /api → localhost:4100.
const app = express();
const PORT = process.env.PORT || 4100;

app.use(cors({ origin: ['http://localhost:5174', 'http://127.0.0.1:5174'] }));
app.use(express.json({ limit: '1mb' }));

/**
 * Initialize DB schema via migrations + ensure the bank signing keypair exists.
 * Called ONLY when the server actually starts (app.listen), NOT at module
 * import time — so test files that import app for supertest don't initialize
 * the production DB before BC_DB_PATH is set.
 *
 * Phase 0 (v5 §二 H1): now calls runMigrations() directly instead of the
 * legacy initSchema() — same effect, more explicit. On failure, throws and
 * the caller (app.listen path below) lets the process exit with non-zero.
 *
 * M3 addition: after runMigrations(), call bankKeyService.getOrGenerate() to
 * provision the singleton row in bank_keys. On first boot this generates a
 * fresh keypair; on subsequent boots it reads the existing row back (no
 * regeneration — would invalidate previously-issued tokens).
 *
 * Phase 1 缺陷修复 (方案 A): after runMigrations() + getOrGenerate(), start
 * the global session cleanup job. It scans expired sessions hourly and
 * refunds them so in-flight amounts don't hang forever. The returned stop()
 * is registered on SIGINT/SIGTERM so the interval is cleared on graceful
 * shutdown.
 */
export function initDatabase() {
  closeDb();  // reset singleton against current BC_DB_PATH (in case it changed)
  const db = getDb();
  runMigrations(db);
  const kp = getOrGenerate();
  console.log(`[backend] Bank public key: ${bytesToHex(kp.publicKey)}`);

  // Phase 1 缺陷修复 (方案 A): start background cleanup job AFTER migrations
  // (so withdrawal_sessions + bank_reserve tables exist). unref'd so it
  // doesn't block process exit.
  const stopCleanup = startCleanupJob();
  process.on('SIGINT', stopCleanup);
  process.on('SIGTERM', stopCleanup);
}

// Health check (namespaced under /api for consistency with the Vite proxy)
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'blindcash-backend', milestone: 'M7' });
});

// Auth routes (register + login — both accept/return a role)
app.use('/api/auth', authRoutes);

// Bank public routes (M3): GET /api/bank/pubkey — no auth, lets anyone fetch
// the bank's public key P for local signature verification.
app.use('/api/bank', bankRoutes);

// Withdrawal routes (M4/M7): 4-move protocol — any logged-in user can withdraw
// (role lock removed for Chaum-style transfer closure).
app.use('/api/withdraw', withdrawalRoutes);

// Payment routes (M5/M7): POST /api/payment deposits a withdrawn token to any
// logged-in user's balance. Format gate + verifySig + atomic BEGIN IMMEDIATE
// live in paymentService.js.
app.use('/api/payment', paymentRoutes);

// Transactions routes (M7): GET /api/transactions — current user's ledger.
app.use('/api/transactions', transactionsRoutes);

// Only start the HTTP server when running as the main entry (not when
// imported by test files — supertest creates its own server from app).
if (process.env.NODE_ENV !== 'test') {
  initDatabase();
  app.listen(PORT, () => {
    console.log(`[backend] BlindCash API listening on http://localhost:${PORT}`);
  });
}

export default app;
