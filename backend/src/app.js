// BlindCash backend entry — M1 scaffold
//
// M1 scope: health check + auth routes (register/login with role).
// Later milestones mount /withdraw, /payment, /bank, /accounts routes.

import express from 'express';
import cors from 'cors';
import { initSchema } from './models/db.js';

import authRoutes from './routes/auth.js';

// NOTE: blindcash uses port 4100 (NOT 4000) so it can run side-by-side with
// the cryptobank project (which uses 4000). The Vite dev server runs on 5174
// (cryptobank uses 5173) and proxies /api → localhost:4100.
const app = express();
const PORT = process.env.PORT || 4100;

app.use(cors({ origin: ['http://localhost:5174', 'http://127.0.0.1:5174'] }));
app.use(express.json({ limit: '1mb' }));

/**
 * Initialize DB schema. Called ONLY when the server actually starts
 * (app.listen), NOT at module import time — so test files that import app
 * for supertest don't initialize the production DB before BC_DB_PATH is set.
 */
export function initDatabase() {
  initSchema();
}

// Health check (namespaced under /api for consistency with the Vite proxy)
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'blindcash-backend', milestone: 'M1' });
});

// Auth routes (register + login — both accept/return a role)
app.use('/api/auth', authRoutes);

// Only start the HTTP server when running as the main entry (not when
// imported by test files — supertest creates its own server from app).
if (process.env.NODE_ENV !== 'test') {
  initDatabase();
  app.listen(PORT, () => {
    console.log(`[backend] BlindCash API listening on http://localhost:${PORT}`);
  });
}

export default app;
