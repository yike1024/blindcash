// models/initDb.js — PostgreSQL bootstrap
//
// Run with: npm run init:db
// Initializes the DB pool, runs migrations, ensures the bank keypair exists.

import { initSchema, getDb } from './db.js';
import { getOrGenerate } from '../services/bankKeyService.js';
import { bytesToHex } from '../utils/hex.js';

async function main() {
  await initSchema();
  const db = getDb();
  console.log('[initDb] PostgreSQL database initialized.');

  const kp = await getOrGenerate();
  console.log(`[initDb] Bank public key: ${bytesToHex(kp.publicKey)}`);

  const tables = await db.prepare(
    `SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`,
  ).all();
  console.log(`[initDb] Tables (${tables.length}): ${tables.map(t => t.tablename).join(', ')}`);

  const indexes = await db.prepare(
    `SELECT indexname FROM pg_indexes WHERE schemaname = 'public' ORDER BY indexname`,
  ).all();
  console.log(`[initDb] Indexes (${indexes.length}): ${indexes.map(i => i.indexname).join(', ')}`);

  console.log('[initDb] Schema initialized successfully.');
  process.exit(0);
}

main().catch((err) => {
  console.error('[initDb] FAILED:', err.message);
  process.exit(1);
});
