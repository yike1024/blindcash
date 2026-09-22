// utils/migrationRunner.js — Phase 0: SQLite migration runner
//
// v5 §二 H1 design (with N2 + P3a + baseline 特判 fixes baked in):
//
//   runMigrations(db) walks three steps:
//     1. Ensure schema_migrations bookkeeping table exists
//     2. Baseline 特判 (M4): if `users` table already exists but version=1
//        not recorded → mark version=1 WITHOUT executing baseline (existing
//        dev DB built from old schema.sql before runner existed — re-running
//        baseline is wasteful for CREATE IF NOT EXISTS and would re-fire
//        any future INSERT-class seed statements).
//        If `users` doesn't exist + version=1 not recorded → execute baseline
//        SQL inside a transaction + record version=1.
//     3. Scan migrations/ dir, apply unapplied versions in filename sort
//        order (matches version order when zero-padded). Each migration
//        runs inside a transaction; failure rolls back + throws.
//
// N2 修正 (删 pending 死代码 + 加版本连续性校验):
//   原 v2 伪代码先查 schema_migrations "pending" 再应用，但 schema_migrations
//   只存"已应用"行，"pending" 永远是空集 → 死代码。正确做法：扫文件系统 +
//   跳过已应用版本。另加 `version !== lastApplied + 1 → warn` 连续性校验，
//   防 cherry-pick 跳号让 005 在 002-004 未应用时直接跑炸。
//
// P3a 修正 (空集边界):
//   `Math.max(...[]) === -Infinity`，首个迁移 `version !== -Infinity + 1`
//   会误 warn 一次。改为 `appliedVersions.size ? Math.max(...) : 0`。
//
// 失败语义: 任何迁移 SQL 抛错 → transaction 回滚 + 函数抛错。app.js 在
// initDatabase() 里 try/catch 后 process.exit(1) — 让进程死得显眼，不留
// 半迁移状态。

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Canonical paths (defaults). Tests can override via runMigrations options.
const MODELS_DIR = join(__dirname, '..', 'models');
const DEFAULT_MIGRATIONS_DIR = join(MODELS_DIR, 'migrations');
const DEFAULT_SCHEMA_MIGRATIONS_DDL_PATH = join(MODELS_DIR, 'schema_migrations.sql');
const DEFAULT_BASELINE_PATH = join(DEFAULT_MIGRATIONS_DIR, '001_init_baseline.sql');

/**
 * Run all pending migrations on the given Database handle.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {object} [opts] — for tests; production calls omit this
 * @param {string} [opts.migrationsDir] — override migrations scan dir
 * @param {string} [opts.baselinePath] — override baseline SQL file path
 * @param {string} [opts.schemaMigrationsPath] — override schema_migrations DDL path
 * @param {(msg:object|string) => void} [opts.warn] — override warn logger (tests)
 * @throws {Error} if any migration file fails to apply (transaction rolled back)
 */
export function runMigrations(db, opts = {}) {
  const migrationsDir = opts.migrationsDir ?? DEFAULT_MIGRATIONS_DIR;
  const baselinePath = opts.baselinePath ?? DEFAULT_BASELINE_PATH;
  const schemaMigrationsPath = opts.schemaMigrationsPath ?? DEFAULT_SCHEMA_MIGRATIONS_DDL_PATH;
  const warn = opts.warn ?? ((msg) => console.warn('[migrationRunner]', msg?.msg ?? msg));

  // 1. Ensure schema_migrations bookkeeping table exists.
  const hasMigrationsTable = db.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'`
  ).get();
  if (!hasMigrationsTable) {
    const ddl = readFileSync(schemaMigrationsPath, 'utf8');
    db.exec(ddl);
  }

  // 2. Baseline 特判 (M4): users exists → mark version=1, skip execution.
  //    Why this special case: re-running baseline on a legacy dev DB is wasteful
  //    for CREATE IF NOT EXISTS, and would re-fire any future INSERT-class seed
  //    statements (none today, but defensive against future baseline changes).
  const usersExists = db.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name='users'`
  ).get();
  const baselineApplied = db.prepare(
    `SELECT 1 FROM schema_migrations WHERE version = 1`
  ).get();

  if (usersExists && !baselineApplied) {
    // Existing dev DB (built from old schema.sql before migrationRunner existed):
    // users table is already there → skip baseline execution, just record version=1.
    db.prepare(
      `INSERT INTO schema_migrations (version, name) VALUES (1, '001_init_baseline')`
    ).run();
  } else if (!usersExists && !baselineApplied) {
    // Fresh DB: run baseline DDL inside a transaction to create all initial
    // tables + indexes. If baseline fails partway, the transaction rolls back
    // and we throw — caller should exit the process.
    const baselineSQL = readFileSync(baselinePath, 'utf8');
    const tx = db.transaction(() => {
      db.exec(baselineSQL);
      db.prepare(
        `INSERT INTO schema_migrations (version, name) VALUES (1, '001_init_baseline')`
      ).run();
    });
    tx();
  }
  // else: baseline already applied — skip silently.

  // 3. Apply subsequent migrations in version order.
  //    N2: scan filesystem, skip already-applied versions. No "pending" query —
  //    schema_migrations only stores "applied", querying it for "pending" was
  //    the dead code v2 had.
  if (!existsSync(migrationsDir)) {
    return;  // migrations/ dir doesn't exist — Phase 0 baseline only, nothing to scan.
  }

  const migrationFiles = readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();  // 字符串排序保证 001 < 002 < ... < 010 (zero-padded)

  const appliedVersions = new Set(
    db.prepare(`SELECT version FROM schema_migrations`).all().map(r => r.version)
  );

  // P3a: Math.max(...[]) === -Infinity → use `size ? Math.max(...) : 0` to
  // avoid a spurious gap-warn on the very first migration when the runner is
  // applied to a DB with no prior migrations recorded (only baseline, which
  // was handled above).
  let lastApplied = appliedVersions.size ? Math.max(...[...appliedVersions]) : 0;

  for (const file of migrationFiles) {
    const version = parseInt(file.split('_')[0], 10);
    if (Number.isNaN(version)) continue;
    if (appliedVersions.has(version)) continue;

    // N2 连续性校验：若 version !== lastApplied + 1，warn 但不阻塞。
    // 有意跳号（比如未 cherry-pick 的迁移文件）会让运维注意到，不至于
    // 让 005 在 002-004 未应用时直接跑炸。
    if (version !== lastApplied + 1) {
      warn({
        msg: 'gap in migration chain',
        file,
        lastApplied,
        thisVersion: version,
      });
    }

    const sql = readFileSync(join(migrationsDir, file), 'utf8');
    const tx = db.transaction(() => {
      db.exec(sql);
      db.prepare(
        `INSERT INTO schema_migrations (version, name) VALUES (?, ?)`
      ).run(version, file.replace(/\.sql$/, ''));
    });
    tx();  // 失败自动回滚 + 抛错；app.js catch 后 process.exit(1)
    lastApplied = version;
  }
}

/**
 * List applied migrations (for /api/admin/migrations or debugging).
 * @param {import('better-sqlite3').Database} db
 * @returns {Array<{version:number, name:string, applied_at:string}>}
 */
export function listAppliedMigrations(db) {
  return db.prepare(
    `SELECT version, name, applied_at FROM schema_migrations ORDER BY version`
  ).all();
}
