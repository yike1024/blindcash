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

    // Simulate a legacy dev DB: users table already exists, built from the
    // old schema.sql before migrationRunner existed. Add a sentinel column
    // 'legacy_marker' so we can prove baseline did NOT replace the table.
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

    // The sentinel column + row must still be there — proves baseline was
    // SKIPPED, not re-executed (which would have failed since CREATE TABLE
    // IF NOT EXISTS wouldn't replace the existing users table anyway, but
    // the legacy_marker column proves no DROP+CREATE happened either).
    const user = db.prepare(
      `SELECT legacy_marker FROM users WHERE username = 'legacy_user'`
    ).get();
    expect(user.legacy_marker).toBe('pre-runner');

    // Other tables (bank_keys etc.) should NOT exist — baseline was skipped,
    // so only the manually-created users table is there. This is the expected
    // behavior per the M4 baseline 特判: we trust that a legacy dev DB has
    // all the tables it needs (since schema.sql was idempotent).
    const tables = db.prepare(
      `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`
    ).all().map(r => r.name);
    expect(tables).not.toContain('bank_keys');
    expect(tables).not.toContain('withdrawal_sessions');
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
    const rowsAfterFirst = listAppliedMigrations(db);
    expect(rowsAfterFirst.length).toBe(1);

    // Run again — should be a no-op.
    runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });
    const rowsAfterSecond = listAppliedMigrations(db);
    expect(rowsAfterSecond.length).toBe(1);
    expect(rowsAfterSecond[0].version).toBe(1);

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

    // Set up a temp migrations dir with a deliberately bad 002 migration.
    const badMigrationsDir = join(DATA_DIR, `bad-migrations-${Date.now()}`);
    mkdirSync(badMigrationsDir, { recursive: true });
    writeFileSync(
      join(badMigrationsDir, '002_bad.sql'),
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

      // version=2 must NOT be recorded (transaction rolled back).
      const v2 = db.prepare(
        `SELECT 1 FROM schema_migrations WHERE version = 2`
      ).get();
      expect(v2).toBeUndefined();

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

    // Set up a temp migrations dir with a 003 file (skipping 002 on purpose).
    // The runner should warn about the gap but still apply 003.
    const gapMigrationsDir = join(DATA_DIR, `gap-migrations-${Date.now()}`);
    mkdirSync(gapMigrationsDir, { recursive: true });
    writeFileSync(
      join(gapMigrationsDir, '003_gap_test.sql'),
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

      // The gap warn should have fired for 003 (lastApplied=1, thisVersion=3).
      const gapWarn = warns.find(w => typeof w === 'object' && w.msg === 'gap in migration chain');
      expect(gapWarn).toBeDefined();
      expect(gapWarn.file).toBe('003_gap_test.sql');
      expect(gapWarn.lastApplied).toBe(1);
      expect(gapWarn.thisVersion).toBe(3);

      // 003 should still have been applied despite the gap warn.
      const v3 = db.prepare(
        `SELECT version, name FROM schema_migrations WHERE version = 3`
      ).get();
      expect(v3).toBeDefined();
      expect(v3.name).toBe('003_gap_test');

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
