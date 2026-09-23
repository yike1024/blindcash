// tests/migrationRunner.test.js — Phase 0: migration runner unit tests
//
// v5 §二 H1 验收矩阵 (5 cases, see plan 验收清单):
//   ✓ fresh DB → baseline 建表 + version=1 记录
//   ✓ existing dev DB (users 已存在) → baseline 特判跳过执行 + 标 version=1
//   ✓ idempotent — 二次调用 runMigrations 不重复应用
//   ✓ 失败迁移 → 事务回滚 + 不写 version 记录 + 进程退出语义
//   ✓ 版本连续性跳号 → warn 但不阻塞（N2 修正）
//
// 测试隔离：每个用例使用独立 TEST_DB_PATH，afterEach closeDb + rmSync。
// 失败/跳号用例使用临时 migrations 目录（自定义 opts.migrationsDir）。

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

import { runMigrations, listAppliedMigrations } from '../src/utils/migrationRunner.js';
import { closeDb } from '../src/models/db.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '..', 'data');

// Resolve real paths for migrations dir / baseline / schema_migrations DDL.
// migrationRunner.js hardcodes these via __dirname; tests re-derive them the
// same way so they can pass them as opts (defaults would also work, but being
// explicit makes the test independent of CWD).
const MODELS_DIR = join(__dirname, '..', 'src', 'models');
const REAL_MIGRATIONS_DIR = join(MODELS_DIR, 'migrations');
const REAL_SCHEMA_MIGRATIONS_DDL = join(MODELS_DIR, 'schema_migrations.sql');
const REAL_BASELINE_PATH = join(REAL_MIGRATIONS_DIR, '001_init_baseline.sql');

// Per-test DB path (reset in beforeEach).
let TEST_DB_PATH;

function makeFreshDb() {
  // Always overwrite TEST_DB_PATH with a fresh file.
  const db = new Database(TEST_DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

describe('Phase 0 migration runner', () => {
  beforeEach(() => {
    TEST_DB_PATH = join(DATA_DIR, `test-p0-migrations-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.db`);
    // Eagerly delete any stale file at this path (the random suffix makes
    // collisions essentially impossible, but be defensive).
    try { rmSync(TEST_DB_PATH); } catch { /* file didn't exist, fine */ }
    try { rmSync(`${TEST_DB_PATH}-shm`); } catch { /* unused */ }
    try { rmSync(`${TEST_DB_PATH}-wal`); } catch { /* unused */ }
  });

  afterEach(() => {
    closeDb();
    try { rmSync(TEST_DB_PATH); } catch { /* already closed */ }
    try { rmSync(`${TEST_DB_PATH}-shm`); } catch { /* unused */ }
    try { rmSync(`${TEST_DB_PATH}-wal`); } catch { /* unused */ }
  });

  // ──────────────────────────────────────────────────────────────────────
  // Case 1: fresh DB → baseline runs + version=1 recorded
  // ──────────────────────────────────────────────────────────────────────
  it('fresh DB applies baseline and records version=1', () => {
    const db = makeFreshDb();

    runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    // All five baseline tables should exist.
    const tables = db.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`
    ).all().map(r => r.name);
    expect(tables).toEqual(expect.arrayContaining([
      'users', 'bank_keys', 'withdrawal_sessions', 'spent_coins', 'transactions',
    ]));
    expect(tables).toContain('schema_migrations');

    // version=1 recorded with the baseline name.
    const row = db.prepare(
      `SELECT version, name FROM schema_migrations WHERE version = 1`
    ).get();
    expect(row).toBeDefined();
    expect(row.version).toBe(1);
    expect(row.name).toBe('001_init_baseline');
  });

  // ──────────────────────────────────────────────────────────────────────
  // Case 2: existing dev DB (users already exists) → baseline 特判 skips
  // execution + marks version=1 without replacing the users table
  // ──────────────────────────────────────────────────────────────────────
  it('existing dev DB skips baseline execution and marks version=1', () => {
    const db = makeFreshDb();

    // Simulate a legacy dev DB: users + transactions already exist, built from
    // the old schema.sql before migrationRunner existed. Add a sentinel column
    // 'legacy_marker' to users so we can prove baseline did NOT replace the table.
    // transactions is needed because migration 009 (redeem_split CHECK) rebuilds
    // it — if it doesn't exist, the SELECT FROM transactions fails.
    db.exec(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('customer','merchant')),
        balance INTEGER NOT NULL DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        legacy_marker TEXT
      );
      INSERT INTO users (username, password_hash, role, balance, legacy_marker)
        VALUES ('legacy_user', 'hash', 'customer', 100, 'pre-runner');
      CREATE TABLE transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('withdraw','deposit','refund')),
        amount INTEGER NOT NULL,
        counterparty TEXT,
        serial BLOB,
        session_id TEXT,
        note TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    // version=1 must be recorded.
    const row = db.prepare(
      `SELECT version, name FROM schema_migrations WHERE version = 1`
    ).get();
    expect(row).toBeDefined();
    expect(row.version).toBe(1);
    expect(row.name).toBe('001_init_baseline');

    // The sentinel column is GONE — 003_users_role_add_admin.sql rebuilt
    // the users table (DROP + CREATE + INSERT…SELECT explicit cols) to add
    // 'admin' to the role CHECK. The legacy_marker column wasn't in the
    // new schema, so the rebuild dropped it. This proves 003 ran.
    // The user DATA was preserved through the rebuild (INSERT…SELECT copied
    // the 6 standard columns, ignoring legacy_marker).
    const user = db.prepare(
      `SELECT username, role FROM users WHERE username = 'legacy_user'`
    ).get();
    expect(user).toBeDefined();
    expect(user.username).toBe('legacy_user');
    expect(user.role).toBe('customer');

    // The legacy_marker column should NOT exist anymore (003 rebuilt the
    // table without it).
    const cols = db.prepare(`PRAGMA table_info(users)`).all().map(r => r.name);
    expect(cols).not.toContain('legacy_marker');

    // Other tables (bank_keys etc.) SHOULD exist — baseline was skipped (no
    // users re-creation), but 002_bank_reserve.sql and 003 ran and created
    // their tables. bank_reserve should exist from 002.
    // Phase 3: 004 (audit_log) + 005 (bank_keys rebuild) + 006 (spent_coins
    // key_version) also ran — bank_keys now has the new multi-key schema.
    const tables = db.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`
    ).all().map(r => r.name);
    expect(tables).toContain('bank_reserve');
    expect(tables).toContain('audit_log');
    expect(tables).toContain('bank_keys');
  });

  // ──────────────────────────────────────────────────────────────────────
  // Case 3: idempotent — second runMigrations call applies nothing new
  // ──────────────────────────────────────────────────────────────────────
  it('is idempotent on second call', () => {
    const db = makeFreshDb();

    runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });
    // Capture row count + checksum after first run.
    // Phase 1: 002_bank_reserve.sql + 003_users_role_add_admin.sql now apply
    // successfully (migrationRunner fixed to handle explicit BEGIN/COMMIT).
    // Phase 3: 004_audit_log + 005_bank_keys_rebuild + 006_spent_coins_key_version
    // Phase 6.1: 007_bank_keys_add_denomination + 008_add_denomination_to_sessions_and_spent_coins
    // Phase 6.2: 009_transactions_add_redeem_split_kind
    // also apply → total 9 migrations.
    const rowsAfterFirst = listAppliedMigrations(db);
    expect(rowsAfterFirst.length).toBe(9);  // 001-009

    // Run again — should be a no-op.
    runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });
    const rowsAfterSecond = listAppliedMigrations(db);
    expect(rowsAfterSecond.length).toBe(9);  // still 9, no new migrations
    expect(rowsAfterSecond[8].version).toBe(9);  // highest version is 009

    // users table should still exist exactly once.
    const usersCount = db.prepare(`SELECT COUNT(*) as c FROM users`).get();
    expect(usersCount.c).toBe(0);  // baseline has no INSERT — table is empty
  });

  // ──────────────────────────────────────────────────────────────────────
  // Case 4: failing migration rolls back transaction + doesn't record version
  // ──────────────────────────────────────────────────────────────────────
  it('rolls back on migration failure and does not record version', () => {
    const db = makeFreshDb();

    // First, apply baseline normally (fresh DB).
    runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    // Set up a temp migrations dir with a deliberately bad 010 migration.
    // Phase 6.2: use 010 (not 009) because the first run already applied 001-009,
    // so a 009_bad.sql would be skipped as "already applied".
    const badMigrationsDir = join(DATA_DIR, `bad-migrations-${Date.now()}`);
    mkdirSync(badMigrationsDir, { recursive: true });
    writeFileSync(
      join(badMigrationsDir, '010_bad.sql'),
      `CREATE TABLE migration_should_not_exist (id INTEGER);\nTHIS IS NOT VALID SQL;\n`,
    );

    try {
      // Expect runMigrations to throw.
      expect(() =>
        runMigrations(db, {
          migrationsDir: badMigrationsDir,
          baselinePath: REAL_BASELINE_PATH,
          schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
        })
      ).toThrow();

      // version=10 must NOT be recorded (transaction rolled back).
      const v10 = db.prepare(
        `SELECT 1 FROM schema_migrations WHERE version = 10`
      ).get();
      expect(v10).toBeUndefined();

      // The partial table from the bad migration must NOT exist (rollback).
      const badTable = db.prepare(
        `SELECT name FROM sqlite_master WHERE type='table' AND name='migration_should_not_exist'`
      ).get();
      expect(badTable).toBeUndefined();

      // Baseline-applied version=1 must still be there (its transaction committed).
      const v1 = db.prepare(
        `SELECT 1 FROM schema_migrations WHERE version = 1`
      ).get();
      expect(v1).toBeDefined();
    } finally {
      rmSync(badMigrationsDir, { recursive: true, force: true });
    }
  });

  // ──────────────────────────────────────────────────────────────────────
  // Case 5: version continuity gap → warn but don't block (N2 修正)
  // ──────────────────────────────────────────────────────────────────────
  it('warns on version gap but still applies the migration (N2 fix)', () => {
    const db = makeFreshDb();

    // Apply baseline first (records version=1).
    runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    // Set up a temp migrations dir with a 011 file (skipping 010 on purpose).
    // Phase 6.2: use 011 (not 010) because the first run already applied 001-009,
    // so a 010_gap_test.sql would be skipped as "already applied".
    // The runner should warn about the gap (9→11, skipping 10) but still apply 011.
    const gapMigrationsDir = join(DATA_DIR, `gap-migrations-${Date.now()}`);
    mkdirSync(gapMigrationsDir, { recursive: true });
    writeFileSync(
      join(gapMigrationsDir, '011_gap_test.sql'),
      `CREATE TABLE gap_test_table (id INTEGER PRIMARY KEY);\n`,
    );

    // Capture warn calls.
    const warns = [];
    const warnSpy = (msg) => warns.push(msg);

    try {
      runMigrations(db, {
        migrationsDir: gapMigrationsDir,
        baselinePath: REAL_BASELINE_PATH,
        schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
        warn: warnSpy,
      });

      // The gap warn should have fired for 011 (lastApplied=9, thisVersion=11).
      const gapWarn = warns.find(w => typeof w === 'object' && w.msg === 'gap in migration chain');
      expect(gapWarn).toBeDefined();
      expect(gapWarn.file).toBe('011_gap_test.sql');
      expect(gapWarn.lastApplied).toBe(9);
      expect(gapWarn.thisVersion).toBe(11);

      // 011 should still have been applied despite the gap warn.
      const v11 = db.prepare(
        `SELECT version, name FROM schema_migrations WHERE version = 11`
      ).get();
      expect(v11).toBeDefined();
      expect(v11.name).toBe('011_gap_test');

      // The gap_test_table should exist.
      const table = db.prepare(
        `SELECT name FROM sqlite_master WHERE type='table' AND name='gap_test_table'`
      ).get();
      expect(table).toBeDefined();
    } finally {
      rmSync(gapMigrationsDir, { recursive: true, force: true });
    }
  });
});
