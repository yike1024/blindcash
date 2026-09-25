// utils/migrationRunner.js — Phase 0: PostgreSQL migration runner
//
// Ported from the SQLite runner. Key changes:
//   - All calls are async (pg).
//   - `sqlite_master` → `information_schema.tables`.
//   - `db.transaction(() => {...})` → db.transaction(fn)（单连接事务，
//     baseline 与每个迁移都在其中执行，避免 pool 上 BEGIN/COMMIT 落到
//     不同连接导致事务形同虚设）。
//   - The baseline special-case (legacy dev DBs) is preserved but adapted to
//     check `information_schema.tables` instead of `sqlite_master`.
//
// runMigrations(db) walks three steps:
//   1. Ensure schema_migrations bookkeeping table exists.
//   2. Baseline special-case: if `users` table exists but version=1 not
//      recorded → mark version=1 WITHOUT executing baseline.
//      If `users` doesn't exist + version=1 not recorded → execute baseline
//      SQL inside a transaction + record version=1.
//   3. Scan migrations/ dir, apply unapplied versions in filename sort order.

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const MODELS_DIR = join(__dirname, '..', 'models');
const DEFAULT_MIGRATIONS_DIR = join(MODELS_DIR, 'migrations');
const DEFAULT_SCHEMA_MIGRATIONS_DDL_PATH = join(MODELS_DIR, 'schema_migrations.sql');
const DEFAULT_BASELINE_PATH = join(DEFAULT_MIGRATIONS_DIR, '001_init_baseline.sql');

/**
 * Check whether a table exists in the current database (PG information_schema).
 */
async function tableExists(db, tableName) {
  const row = await db.prepare(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_name = $1`
  ).get(tableName);
  return !!row;
}

/**
 * Run all pending migrations.
 *
 * @param {object} db — from getDb() (has prepare/exec)
 * @param {object} [opts] — for tests; production calls omit this
 */
export async function runMigrations(db, opts = {}) {
  const migrationsDir = opts.migrationsDir ?? DEFAULT_MIGRATIONS_DIR;
  const baselinePath = opts.baselinePath ?? DEFAULT_BASELINE_PATH;
  const schemaMigrationsPath = opts.schemaMigrationsPath ?? DEFAULT_SCHEMA_MIGRATIONS_DDL_PATH;
  const warn = opts.warn ?? ((msg) => console.warn('[migrationRunner]', msg?.msg ?? msg));

  // 1. Ensure schema_migrations bookkeeping table exists.
  const hasMigrationsTable = await tableExists(db, 'schema_migrations');
  if (!hasMigrationsTable) {
    const ddl = readFileSync(schemaMigrationsPath, 'utf8');
    await db.exec(ddl);
  }

  // 2. Baseline special-case.
  const usersExists = await tableExists(db, 'users');
  const baselineApplied = await db.prepare(
    `SELECT 1 FROM schema_migrations WHERE version = 1`
  ).get();

  if (usersExists && !baselineApplied) {
    // Existing DB built before migrationRunner existed: record version=1 only.
    await db.prepare(
      `INSERT INTO schema_migrations (version, name) VALUES (1, '001_init_baseline')`
    ).run();
  } else if (!usersExists && !baselineApplied) {
    // Fresh DB: run baseline DDL inside a single-connection transaction.
    const baselineSQL = readFileSync(baselinePath, 'utf8');
    await db.transaction(async (tx) => {
      await tx.exec(baselineSQL);
      await tx.prepare(
        `INSERT INTO schema_migrations (version, name) VALUES (1, '001_init_baseline')`
      ).run();
    });
  }

  // 3. Apply subsequent migrations in version order.
  if (!existsSync(migrationsDir)) return;

  const migrationFiles = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const appliedRows = await db.prepare(`SELECT version FROM schema_migrations`).all();
  const appliedVersions = new Set(appliedRows.map((r) => r.version));

  let lastApplied = appliedVersions.size ? Math.max(...[...appliedVersions]) : 0;

  for (const file of migrationFiles) {
    const version = parseInt(file.split('_')[0], 10);
    if (Number.isNaN(version)) continue;
    if (appliedVersions.has(version)) continue;

    if (version !== lastApplied + 1) {
      warn({ msg: 'gap in migration chain', file, lastApplied, thisVersion: version });
    }

    const sql = readFileSync(join(migrationsDir, file), 'utf8');

    // 每个迁移在单连接事务里执行：DDL 与 version 记录要么一起提交，
    // 要么一起回滚。db.transaction 在 pool-backed db 上开单连接事务，
    // 避免 pool.query 每次落到不同连接导致 BEGIN/COMMIT 形同虚设。
    await db.transaction(async (tx) => {
      await tx.exec(sql);
      await tx.prepare(
        `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`
      ).run(version, file.replace(/\.sql$/, ''));
    });
    lastApplied = version;
  }
}

/**
 * List applied migrations (for /api/admin/migrations or debugging).
 */
export async function listAppliedMigrations(db) {
  return db.prepare(
    `SELECT version, name, applied_at FROM schema_migrations ORDER BY version`
  ).all();
}
