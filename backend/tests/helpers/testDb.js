// tests/helpers/testDb.js — shared PostgreSQL test setup
//
// Replaces the old SQLite per-file BC_DB_PATH isolation. All test files share
// one PostgreSQL test database (DATABASE_URL) and call resetTestDb() in
// beforeAll to drop & recreate all tables for a clean slate.

import { getDb, resetDb, closeDb } from '../../src/models/db.js';

/**
 * Drop all tables and re-run migrations. Call in beforeAll (or beforeEach if
 * finer isolation is needed).
 */
export async function resetTestDb() {
  await resetDb();
}

/** Return the shared db wrapper (getDb()). */
export function getTestDb() {
  return getDb();
}

/** Close the connection pool. Call in afterAll. */
export async function closeTestDb() {
  await closeDb();
}

/**
 * Ensure DATABASE_URL is set. Tests that need a real PG connection should
 * call this at module top-level. Falls back to a default local PG URL for
 * convenience during local dev.
 */
export function ensureDatabaseUrl() {
  if (!process.env.DATABASE_URL) {
    // Use 127.0.0.1 instead of localhost to avoid IPv6 (::1) resolution
    // failures on machines where the PG listener is IPv4-only.
    process.env.DATABASE_URL = 'postgres://postgres:testpass@127.0.0.1:5432/blindcash_test';
  }
  if (!process.env.BC_MASTER_KEY) {
    process.env.BC_MASTER_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  }
  return process.env.DATABASE_URL;
}
