// tests/migrationRunner.test.js — Phase 0: migration runner unit tests (PostgreSQL)
//
// v5 §二 H1 验收矩阵 (5 cases):
//   ✓ fresh DB → baseline 建表 + version=1 记录
//   ✓ existing dev DB (users 已存在) → baseline 特判跳过执行 + 标 version=1
//   ✓ idempotent — 二次调用 runMigrations 不重复应用
//   ✓ 失败迁移 → 事务回滚 + 不写 version 记录
//   ✓ 版本连续性跳号 → warn 但不阻塞
//
// 测试隔离：每个用例前 resetDb() 清空 public schema 后重建。
// 失败/跳号用例使用临时 migrations 目录（自定义 opts.migrationsDir）。

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runMigrations, listAppliedMigrations } from '../src/utils/migrationRunner.js';
import { getDb, resetDb, closeDb } from '../src/models/db.js';
import { ensureDatabaseUrl } from './helpers/testDb.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '..', 'data');
ensureDatabaseUrl();

const MODELS_DIR = join(__dirname, '..', 'src', 'models');
const REAL_MIGRATIONS_DIR = join(MODELS_DIR, 'migrations');
const REAL_SCHEMA_MIGRATIONS_DDL = join(MODELS_DIR, 'schema_migrations.sql');
const REAL_BASELINE_PATH = join(REAL_MIGRATIONS_DIR, '001_init_baseline.sql');

describe('Phase 0 migration runner', () => {
  beforeEach(async () => {
    await resetDb();
  });

  afterEach(async () => {
    await closeDb();
  });

  it('fresh DB applies baseline and records version=1', async () => {
    const db = getDb();

    await runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    const tables = (await db.prepare(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name`
    ).all()).map(r => r.table_name);

    expect(tables).toEqual(expect.arrayContaining([
      'users', 'bank_keys', 'withdrawal_sessions', 'spent_coins', 'transactions',
    ]));
    expect(tables).toContain('schema_migrations');

    const row = await db.prepare(
      `SELECT version, name FROM schema_migrations WHERE version = 1`
    ).get();
    expect(row).toBeDefined();
    expect(row.version).toBe(1);
    expect(row.name).toBe('001_init_baseline');
  });

  it('existing dev DB skips baseline execution and marks version=1', async () => {
    const db = getDb();

    await db.exec(`DROP TABLE IF EXISTS transactions CASCADE;`);
    await db.exec(`DROP TABLE IF EXISTS users CASCADE;`);
    await db.exec(`DROP TABLE IF EXISTS schema_migrations CASCADE;`);
    await db.exec(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('customer','merchant')),
        balance INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        legacy_marker TEXT
      );
      INSERT INTO users (username, password_hash, role, balance, legacy_marker)
        VALUES ('legacy_user', 'hash', 'customer', 100, 'pre-runner');
      CREATE TABLE transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('withdraw','deposit','refund')),
        amount INTEGER NOT NULL,
        counterparty TEXT,
        serial BYTEA,
        session_id TEXT,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    await runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    const row = await db.prepare(
      `SELECT version, name FROM schema_migrations WHERE version = 1`
    ).get();
    expect(row).toBeDefined();
    expect(row.version).toBe(1);
    expect(row.name).toBe('001_init_baseline');

    const user = await db.prepare(
      `SELECT username, role FROM users WHERE username = 'legacy_user'`
    ).get();
    expect(user).toBeDefined();
    expect(user.username).toBe('legacy_user');
    expect(user.role).toBe('customer');

    const cols = (await db.prepare(
      `SELECT column_name FROM information_schema.columns WHERE table_name = 'users'`
    ).all()).map(r => r.column_name);
    // On PostgreSQL, migration 003 is a no-op (baseline already includes
    // 'admin' in the role CHECK), so the users table is NOT rebuilt. The
    // legacy_marker column therefore persists — proving the baseline was
    // skipped (a fresh baseline run would have created users without it).
    expect(cols).toContain('legacy_marker');

    const tables = (await db.prepare(
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`
    ).all()).map(r => r.table_name);
    expect(tables).toContain('bank_reserve');
    expect(tables).toContain('audit_log');
    expect(tables).toContain('bank_keys');
  });

  it('is idempotent on second call', async () => {
    const db = getDb();

    await runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    const rowsAfterFirst = await listAppliedMigrations(db);
    expect(rowsAfterFirst.length).toBe(10);

    await runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });
    const rowsAfterSecond = await listAppliedMigrations(db);
    expect(rowsAfterSecond.length).toBe(10);
    expect(rowsAfterSecond[9].version).toBe(10);

    const usersCount = await db.prepare(`SELECT COUNT(*)::int AS c FROM users`).get();
    expect(usersCount.c).toBe(0);
  });

  it('rolls back on migration failure and does not record version', async () => {
    const db = getDb();

    await runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    const badMigrationsDir = join(DATA_DIR, `bad-migrations-${Date.now()}`);
    mkdirSync(badMigrationsDir, { recursive: true });
    writeFileSync(
      join(badMigrationsDir, '011_bad.sql'),
      `CREATE TABLE migration_should_not_exist (id INTEGER);\nTHIS IS NOT VALID SQL;\n`,
    );

    try {
      await expect(
        runMigrations(db, {
          migrationsDir: badMigrationsDir,
          baselinePath: REAL_BASELINE_PATH,
          schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
        })
      ).rejects.toThrow();

      const v11 = await db.prepare(
        `SELECT 1 FROM schema_migrations WHERE version = 11`
      ).get();
      expect(v11).toBeNull();

      const badTable = await db.prepare(
        `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'migration_should_not_exist'`
      ).get();
      expect(badTable).toBeNull();

      const v1 = await db.prepare(
        `SELECT 1 FROM schema_migrations WHERE version = 1`
      ).get();
      expect(v1).toBeDefined();
    } finally {
      rmSync(badMigrationsDir, { recursive: true, force: true });
    }
  });

  it('warns on version gap but still applies the migration', async () => {
    const db = getDb();

    await runMigrations(db, {
      migrationsDir: REAL_MIGRATIONS_DIR,
      baselinePath: REAL_BASELINE_PATH,
      schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
    });

    const gapMigrationsDir = join(DATA_DIR, `gap-migrations-${Date.now()}`);
    mkdirSync(gapMigrationsDir, { recursive: true });
    writeFileSync(
      join(gapMigrationsDir, '012_gap_test.sql'),
      `CREATE TABLE gap_test_table (id INTEGER PRIMARY KEY);\n`,
    );

    const warns = [];
    const warnSpy = (msg) => warns.push(msg);

    try {
      await runMigrations(db, {
        migrationsDir: gapMigrationsDir,
        baselinePath: REAL_BASELINE_PATH,
        schemaMigrationsPath: REAL_SCHEMA_MIGRATIONS_DDL,
        warn: warnSpy,
      });

      const gapWarn = warns.find(w => typeof w === 'object' && w.msg === 'gap in migration chain');
      expect(gapWarn).toBeDefined();
      expect(gapWarn.file).toBe('012_gap_test.sql');
      expect(gapWarn.lastApplied).toBe(10);
      expect(gapWarn.thisVersion).toBe(12);

      const v12 = await db.prepare(
        `SELECT version, name FROM schema_migrations WHERE version = 12`
      ).get();
      expect(v12).toBeDefined();
      expect(v12.name).toBe('012_gap_test');

      const table = await db.prepare(
        `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'gap_test_table'`
      ).get();
      expect(table).toBeDefined();
    } finally {
      rmSync(gapMigrationsDir, { recursive: true, force: true });
    }
  });
});
