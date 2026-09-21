// models/db.js — M1: SQLite connection layer (better-sqlite3, WAL mode)
//
// Singleton Database handle + helpers for transactions.
// better-sqlite3 is SYNCHRONOUS, which fits SQLite's single-writer model and
// makes BEGIN IMMEDIATE double-spend logic trivial (used in later milestones).
//
// WAL mode: concurrent reads + serialized writes. BEGIN IMMEDIATE acquires the
// write lock up-front → a concurrent double-spend attempt blocks until the
// first transaction commits, then sees the spent row.

import Database from 'better-sqlite3';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = join(__dirname, 'schema.sql');

let _db = null;

/**
 * Resolve the DB path LAZILY (at first getDb() call, not at import time).
 * Allows test files to set process.env.BC_DB_PATH in their module body
 * (which runs AFTER ESM imports are hoisted) and have it take effect.
 */
function resolveDbPath() {
  return process.env.BC_DB_PATH || join(__dirname, '..', '..', 'data', 'blindcash.db');
}

/** Backward-compat: export the resolved path (computed lazily). */
export const DB_PATH = new Proxy({}, {
  get: () => resolveDbPath(),
  toString: () => resolveDbPath(),
});

/**
 * Open (or return the cached) Database handle. Idempotent across calls.
 * @returns {import('better-sqlite3').Database}
 */
export function getDb() {
  if (_db) return _db;
  const dbPath = resolveDbPath();
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  _db = db;
  return db;
}

/**
 * Close the database connection. Used by tests to release the file handle.
 */
export function closeDb() {
  if (_db) {
    _db.close();
    _db = null;
  }
}

/**
 * Run the schema.sql DDL. Idempotent (CREATE TABLE IF NOT EXISTS).
 * Safe to call on every backend boot.
 *
 * NOTE: calls closeDb() first so that if process.env.BC_DB_PATH changed
 * (e.g. a test file switching to its own test DB), the singleton _db is
 * reset and reopened against the new path.
 */
export function initSchema() {
  closeDb();
  const db = getDb();
  const sql = readFileSync(SCHEMA_PATH, 'utf8');
  db.exec(sql);
}

/**
 * Begin an IMMEDIATE transaction (acquires write lock immediately).
 * Used for double-spend protection in M4/M5:
 *   BEGIN IMMEDIATE;
 *   -- check spent_coins for serial
 *   -- insert spent_coins + update merchant.balance
 *   COMMIT;
 *
 * @param {(db: import('better-sqlite3').Database) => any} fn work inside the tx; throw → rollback
 * @returns {any} whatever fn returns on commit
 */
export function runImmediateTx(fn) {
  const db = getDb();
  const tx = db.transaction(() => fn(db));
  return tx.immediate();
}

/** Convenience: run a parameterized query and return all rows. */
export function queryAll(sql, params = []) {
  return getDb().prepare(sql).all(...params);
}

/** Convenience: run a parameterized query and return the first row (or undefined). */
export function queryOne(sql, params = []) {
  return getDb().prepare(sql).get(...params);
}

/** Convenience: run a parameterized write and return RunResult {changes, lastInsertRowid}. */
export function runWrite(sql, params = []) {
  return getDb().prepare(sql).run(...params);
}
