// models/db.js — PostgreSQL connection layer (pg, connection pool)
//
// Migrated from better-sqlite3 (synchronous) to node-postgres (asynchronous).
// To minimize churn across the service layer, this module exposes a
// better-sqlite3–flavoured API:
//   getDb()                 → { prepare(sql), exec(sql), pragma() }
//   prepare(sql).run(...p)  → Promise<{ changes, lastInsertRowid }>
//   prepare(sql).get(...p)  → Promise<row | null>
//   prepare(sql).all(...p)  → Promise<row[]>
//   queryAll / queryOne / runWrite — async convenience wrappers
//   runImmediateTx(fn)      → async transaction; fn receives a tx-db
//
// Differences from the old SQLite layer:
//   - Every DB call is now async (must be awaited).
//   - `?` placeholders are rewritten to `$1, $2, …` automatically.
//   - INSERT statements get `RETURNING id` appended so lastInsertRowid works.
//   - BEGIN IMMEDIATE becomes a plain BEGIN (PG handles write locking via MVCC).
//   - PRAGMA statements are no-ops (PG enforces FKs by default; WAL is built-in).

import pg from 'pg';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runMigrations } from '../utils/migrationRunner.js';

const { Pool } = pg;
const __dirname = dirname(fileURLToPath(import.meta.url));

let _pool = null;

// ── pg type parsers ────────────────────────────────────────────────────────
// Return TIMESTAMP / TIMESTAMPTZ as strings (not Date objects) so the existing
// code that parses `retired_until` with `new Date(s + 'Z')` keeps working.
// INT8 (bigint) → number (balances fit in JS safe-integer range).
//
// We store all timestamps as UTC (via new Date().toISOString()). TIMESTAMP
// (without TZ) returns a naive string; appending 'Z' makes `new Date(s)`
// parse it as UTC instead of local time (which would shift it by the TZ offset).
pg.types.setTypeParser(1114, (v) => v == null ? v : v + 'Z'); // TIMESTAMP → UTC
pg.types.setTypeParser(1184, (v) => v);          // TIMESTAMPTZ (already TZ-aware)
pg.types.setTypeParser(20, (v) => parseInt(v, 10)); // INT8 → number

/**
 * Resolve the PostgreSQL connection string from env.
 * Render provides DATABASE_URL automatically for managed Postgres instances.
 */
function resolveConnectionString() {
  const url = process.env.DATABASE_URL || process.env.PG_CONNECTION_STRING;
  if (!url) {
    throw new Error(
      'DATABASE_URL environment variable is required to connect to PostgreSQL. ' +
      'Set it to a postgres:// connection string (Render supplies this automatically).'
    );
  }
  return url;
}

/**
 * Resolve the SSL config for the pg pool.
 * - PG_SSL=disable → 关闭 SSL（本地无 SSL 的 postgres，如 docker compose 的
 *   postgres:16-alpine）。
 * - PG_SSL=require → 强制 SSL。
 * - 未设置 → 生产环境（NODE_ENV=production，如 Render 托管 PG）默认 require，
 *   否则关闭。rejectUnauthorized:false 容忍自签名证书。
 */
function resolveSslConfig() {
  const mode = process.env.PG_SSL;
  if (mode === 'disable') return false;
  if (mode === 'require') return { rejectUnauthorized: false };
  return process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false;
}

/**
 * Return (and lazily create) the shared connection pool.
 */
export function getPool() {
  if (!_pool) {
    const connectionString = resolveConnectionString();
    _pool = new Pool({
      connectionString,
      ssl: resolveSslConfig(),
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
  }
  return _pool;
}

// ── Placeholder conversion ─────────────────────────────────────────────────
// SQLite `?` → PostgreSQL `$1, $2, …`
function toPgParams(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

// Cache of which tables have an `id` column (so we know whether RETURNING id
// is valid for a given INSERT). Populated lazily from information_schema.
const _tableHasIdCache = new Map();

/**
 * Check whether a table has an `id` column. Uses the provided client (which
 * may be a pool or a transaction client) and caches the result.
 */
async function tableHasIdColumn(client, tableName) {
  const cached = _tableHasIdCache.get(tableName);
  if (cached !== undefined) return cached;
  const row = await client.query(
    `SELECT 1 FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'id'`,
    [tableName],
  );
  const has = row.rows.length > 0;
  _tableHasIdCache.set(tableName, has);
  return has;
}

/**
 * Parse the target table name from an INSERT statement.
 */
function parseInsertTable(sql) {
  const m = sql.match(/^\s*INSERT\s+INTO\s+(?:IF\s+NOT\s+EXISTS\s+)?["`]?(\w+)["`]?/i);
  return m ? m[1] : null;
}

/**
 * Build a statement object that mimics better-sqlite3's
 * `db.prepare(sql).run/get/all(...)` API, but backed by a pg client/pool.
 *
 * - `run()` returns { changes: rowCount, lastInsertRowid }.
 *   INSERT statements without an explicit RETURNING clause get `RETURNING id`
 *   appended automatically (only if the target table has an `id` column) so
 *   lastInsertRowid is populated.
 * - `get()` returns the first row or null.
 * - `all()` returns all rows.
 *
 * @param {pg.Pool | pg.PoolClient} client
 * @param {string} sql — original SQL with `?` placeholders
 */
function createStatement(client, sql) {
  const pgSql = toPgParams(sql);
  const isInsert = /^\s*INSERT\s+/i.test(sql);
  const hasReturning = /\bRETURNING\b/i.test(sql);
  const insertTable = isInsert ? parseInsertTable(sql) : null;

  return {
    async run(...params) {
      let finalSql = pgSql;
      if (isInsert && !hasReturning && insertTable) {
        const hasId = await tableHasIdColumn(client, insertTable);
        if (hasId) finalSql = `${pgSql} RETURNING id`;
      }
      const res = await client.query(finalSql, params);
      return {
        changes: res.rowCount,
        lastInsertRowid: isInsert ? (res.rows?.[0]?.id ?? null) : null,
      };
    },
    async get(...params) {
      const res = await client.query(pgSql, params);
      return res.rows[0] ?? null;
    },
    async all(...params) {
      const res = await client.query(pgSql, params);
      return res.rows;
    },
  };
}

/**
 * Build a "database" object backed by the pool (for non-transactional use).
 * Each call returns a fresh wrapper around the same underlying pool.
 */
export function getDb() {
  const pool = getPool();
  return {
    prepare: (sql) => createStatement(pool, sql),
    exec: async (sql) => { await pool.query(sql); },
    pragma: () => { /* no-op: PG has no PRAGMA */ },
    // 在单连接上跑事务。pool-backed db 需要它来保证 BEGIN/COMMIT 与
    // 中间语句落在同一连接（pool.query 每次可能命中不同连接）。
    transaction: (fn) => runImmediateTx(fn),
  };
}

/**
 * Close the connection pool. Used by tests to release resources.
 */
export async function closeDb() {
  if (_pool) {
    await _pool.end();
    _pool = null;
  }
}

/**
 * Initialize DB schema via the migration runner. Idempotent — safe to call
 * on every boot and on test setup.
 */
export async function initSchema() {
  const db = getDb();
  await runMigrations(db);
}

/**
 * Drop all tables in the public schema and re-run migrations. Used by tests
 * to guarantee a clean slate between test files (SQLite used separate DB
 * files; PostgreSQL uses one shared test DB).
 */
export async function resetDb() {
  const pool = getPool();
  await pool.query(`
    DO $$ DECLARE r record;
    BEGIN
      FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
        EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
      END LOOP;
    END $$;
  `);
  await runMigrations(getDb());
}

/**
 * Run a transaction. `fn` receives a transactional db object whose
 * `prepare()` runs on the same client (same connection). On throw, the
 * transaction is rolled back; otherwise committed.
 *
 * Replaces better-sqlite3's `db.transaction(() => fn()).immediate()`.
 *
 * @param {(db: object) => Promise<any>} fn — async work inside the tx
 * @returns {Promise<any>} whatever fn returns on commit
 */
export async function runImmediateTx(fn) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const txDb = {
      prepare: (sql) => createStatement(client, sql),
      exec: async (sql) => { await client.query(sql); },
      // 已在该单连接事务内：嵌套调用直接复用，不再开新事务。
      transaction: async (fn) => fn(txDb),
    };
    const result = await fn(txDb);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/** Convenience: run a parameterized query and return all rows. */
export async function queryAll(sql, params = []) {
  return getDb().prepare(sql).all(...params);
}

/** Convenience: run a parameterized query and return the first row (or null). */
export async function queryOne(sql, params = []) {
  return getDb().prepare(sql).get(...params);
}

/** Convenience: run a parameterized write and return { changes, lastInsertRowid }. */
export async function runWrite(sql, params = []) {
  return getDb().prepare(sql).run(...params);
}
