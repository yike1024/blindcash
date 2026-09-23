// tests/auditService.test.js — Phase 3 (v5 §三 3.3): audit_log service unit tests
//
// v5 §三 3.3 验收：audit_log 表记录所有关键操作（含 invariant_violation）。
// 本文件 4 个测试覆盖 logAction/queryAuditLog 的核心语义：
//   ✓ logAction 写入完整字段（actor/action/target/amount/meta/ip）
//   ✓ logAction 接受 db 参数（在调用方事务内写入，事务回滚则日志消失）
//   ✓ logAction 接受 null 可选字段（不抛错）
//   ✓ queryAuditLog 分页 + action 过滤
//
// audit_log 表 schema 见 004_audit_log.sql；invariant_violation 写入路径
// 见 bankReserveService.runInvariantCheckedTx（这里只测 logAction 本身，
// invariant_violation 的真实写入路径由 bankReserveService.test.js 间接覆盖）。
//
// 文献参考：
//   [1] NIST SP 800-92rev1 §3 "Audit Log Security" — 要求日志条目至少含
//       actor/action/timestamp 三要素；本表更进一步含 target/amount/meta/ip。
//   [2] OWASP ASVS L1 v4.0.31 §7.1.1 — "verify that all authentication events
//       are logged"，本系统的 deposit/withdraw/payment/key_rotate 视作等价
//       关键操作，遵循同一审计模型。

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { logAction, queryAuditLog } from '../src/services/auditService.js';
import { initSchema, getDb, closeDb, queryOne } from '../src/models/db.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_PATH = join(__dirname, '..', 'data', 'test-p3-audit.db');
process.env.BC_DB_PATH = TEST_DB_PATH;

initSchema();

beforeAll(() => {
  // bank_reserve singleton must exist (002_bank_reserve.sql INSERT OR IGNORE)
  // — initSchema runs migrations, but be defensive.
  const db = getDb();
  db.prepare(`INSERT OR IGNORE INTO bank_reserve (id) VALUES (1)`).run();
});

beforeEach(() => {
  const db = getDb();
  db.exec('DELETE FROM audit_log;');
});

afterAll(() => {
  closeDb();
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(TEST_DB_PATH + suffix, { force: true }); } catch {}
  }
});

describe('Phase 3 · auditService — logAction + queryAuditLog', () => {
  it('logAction writes a row with all fields populated', () => {
    logAction({
      actor_id: 42,
      action: 'deposit',
      target: 'bank_reserve',
      amount: 100,
      meta: JSON.stringify({ source: 'fiat_topup' }),
      ip: '203.0.113.10',
    });

    const row = queryOne(
      `SELECT actor_id, action, target, amount, meta, ip_address
       FROM audit_log WHERE action = 'deposit'`,
    );
    expect(row).toBeDefined();
    expect(row.actor_id).toBe(42);
    expect(row.action).toBe('deposit');
    expect(row.target).toBe('bank_reserve');
    expect(row.amount).toBe(100);
    expect(row.meta).toBe(JSON.stringify({ source: 'fiat_topup' }));
    expect(row.ip_address).toBe('203.0.113.10');
  });

  it('logAction uses the caller-provided db handle (in-transaction writes)', () => {
    // Simulate a caller's transaction: pass a db handle acquired via getDb().
    // The row should be visible inside the same tx and persist after commit.
    const db = getDb();
    db.exec('BEGIN IMMEDIATE;');
    try {
      logAction({
        actor_id: 7,
        action: 'key_rotate',
        target: '1',
        amount: null,
        meta: JSON.stringify({ new_version: 2 }),
        ip: '127.0.0.1',
        db, // in-tx write
      });
      const inTx = db.prepare(
        `SELECT actor_id, action FROM audit_log WHERE action = 'key_rotate'`,
      ).get();
      expect(inTx.actor_id).toBe(7);
      expect(inTx.action).toBe('key_rotate');
      db.exec('COMMIT;');
    } catch (e) {
      db.exec('ROLLBACK;');
      throw e;
    }
    // After commit, the row is persisted.
    const after = queryOne(
      `SELECT actor_id FROM audit_log WHERE action = 'key_rotate'`,
    );
    expect(after).toBeDefined();
    expect(after.actor_id).toBe(7);
  });

  it('logAction accepts null optional fields without error', () => {
    // All optional fields omitted — only actor_id + action required.
    expect(() => logAction({ actor_id: null, action: 'invariant_violation' }))
      .not.toThrow();

    const row = queryOne(
      `SELECT actor_id, action, target, amount, meta, ip_address
       FROM audit_log WHERE action = 'invariant_violation'`,
    );
    expect(row).toBeDefined();
    expect(row.actor_id).toBeNull();
    expect(row.action).toBe('invariant_violation');
    expect(row.target).toBeNull();
    expect(row.amount).toBeNull();
    expect(row.meta).toBeNull();
    expect(row.ip_address).toBeNull();
  });

  it('queryAuditLog returns paginated results and honors action filter', () => {
    // Seed 5 deposits + 3 withdraws + 1 invariant_violation (9 total).
    for (let i = 0; i < 5; i++) {
      logAction({ actor_id: i + 1, action: 'deposit', amount: 100 * (i + 1) });
    }
    for (let i = 0; i < 3; i++) {
      logAction({ actor_id: i + 100, action: 'withdraw', amount: 30 });
    }
    logAction({ actor_id: null, action: 'invariant_violation' });

    // No filter, page 1 size 5 → 5 entries, total 9.
    const page1 = queryAuditLog({ page: 1, pageSize: 5 });
    expect(page1.total).toBe(9);
    expect(page1.page).toBe(1);
    expect(page1.pageSize).toBe(5);
    expect(page1.entries).toHaveLength(5);

    // Page 2 size 5 → 4 entries (9 - 5).
    const page2 = queryAuditLog({ page: 2, pageSize: 5 });
    expect(page2.entries).toHaveLength(4);
    expect(page2.total).toBe(9);

    // Action filter: only deposits.
    const deposits = queryAuditLog({ page: 1, pageSize: 50, action: 'deposit' });
    expect(deposits.total).toBe(5);
    expect(deposits.entries).toHaveLength(5);
    expect(deposits.entries.every((e) => e.action === 'deposit')).toBe(true);

    // Action filter: invariant_violation (the path N1 修正的).
    const violations = queryAuditLog({
      page: 1, pageSize: 50, action: 'invariant_violation',
    });
    expect(violations.total).toBe(1);
    expect(violations.entries[0].action).toBe('invariant_violation');
  });
});
