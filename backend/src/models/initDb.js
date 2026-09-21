// models/initDb.js — M1: create the DB file + run schema.sql
//
// Run with: npm run init:db
// Safe to re-run — uses CREATE TABLE IF NOT EXISTS.

import { initSchema, getDb, DB_PATH } from './db.js';

console.log(`[initDb] Database path: ${DB_PATH}`);
initSchema();
const db = getDb();

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
