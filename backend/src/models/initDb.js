// models/initDb.js — M1 + M3: create the DB file, run schema.sql, ensure
// the bank signing keypair exists.
//
// Run with: npm run init:db
// Safe to re-run — uses CREATE TABLE IF NOT EXISTS and idempotent keypair
// provisioning (getOrGenerate() only INSERTs if no row exists).

import { initSchema, getDb } from './db.js';
import { getOrGenerate } from '../services/bankKeyService.js';
import { bytesToHex } from '../utils/hex.js';

initSchema();
const db = getDb();
console.log(`[initDb] Database path: ${db.name}`);

// M3: ensure the bank signing keypair exists (singleton row id=1).
// On first boot this generates x ∈ [1, n-1], P = x·G and persists them.
// On subsequent boots it reads the existing row back (no regeneration —
// regenerating would invalidate every previously-issued token).
const kp = getOrGenerate();
console.log(`[initDb] Bank public key: ${bytesToHex(kp.publicKey)}`);

// Sanity: list tables created
const tables = db.prepare(
  "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
).all();
console.log(`[initDb] Tables (${tables.length}): ${tables.map(t => t.name).join(', ')}`);

const indexes = db.prepare(
  "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name"
).all();
console.log(`[initDb] Indexes (${indexes.length}): ${indexes.map(i => i.name).join(', ')}`);

const pragmas = db.prepare("PRAGMA journal_mode").get();
console.log(`[initDb] journal_mode = ${pragmas.journal_mode}`);
const fk = db.prepare("PRAGMA foreign_keys").get();
console.log(`[initDb] foreign_keys = ${fk.foreign_keys}`);

console.log('[initDb] Schema initialized successfully.');
