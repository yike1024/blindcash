// tests/admin.test.js — Phase 3 (v5 §三 3.3): admin routes + requireAdmin middleware
//
// v5 §三 3.3 验收：
//   ✓ 管理员能分页查询审计日志
//   ✓ 普通用户查审计日志 → 403
//   ✓ POST /api/admin/rotate-key 触发密钥轮换（admin only）
//
// 本文件 5 个测试覆盖 admin 路由的权限边界 + 核心功能：
//   ✓ GET /api/admin/audit 无 Authorization → 401
//   ✓ GET /api/admin/audit customer token → 403 FORBIDDEN
//   ✓ GET /api/admin/audit admin token → 200 + 分页结构
//   ✓ GET /api/admin/audit?action=deposit admin → 只返回 deposit 行
//   ✓ POST /api/admin/rotate-key admin → 200 + 新旧 key_version
//
// 权限模型：authenticateJWT → requireAdmin（顺序敏感，requireAdmin 依赖
// req.user.role 由 authenticateJWT 设置）。requireAdmin 在 role !== 'admin'
// 时返回 403，在 req.user 缺失时返回 401（前置 authenticateJWT 已挡一道）。
//
// 文献参考：
//   [1] OWASP ASVS L1 v4.0.31 §4.1.3 — "verify that the application enforces
//       access controls [...] on a per-request basis"。requireAdmin 中间件
//       即此 per-request enforcement 的实现。
//   [2] NIST SP 800-53rev5 AC-3 "Access Enforcement" — 强制主体（user）
//       必须经显式授权才能访问客体（audit_log / rotate-key），本测试
//       通过 customer token 被拒来验证否定授权语义。

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

import app from '../src/app.js';
import { getDb, closeDb, queryOne } from '../src/models/db.js';
import { resetTestDb, ensureDatabaseUrl, closeTestDb } from './helpers/testDb.js';
import { logAction } from '../src/services/auditService.js';
import { createUser } from '../src/services/userService.js';
import { hashPassword, generateToken } from '../src/services/authService.js';
import { getOrGenerate, getActiveKeyVersion, _resetCacheForTest } from '../src/services/bankKeyService.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
ensureDatabaseUrl();
const server = http.createServer(app);
let baseUrl;

async function api (path, { method = 'GET', token, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let json;
  try { json = await res.json(); } catch { json = null; }
  return { status: res.status, body: json };
}

const ADMIN = { username: 'root_admin', password: 'RootPass!1', role: 'admin' };
const CUSTOMER = { username: 'alice_customer', password: 'Passw0rd!', role: 'customer' };

let adminToken, customerToken;

beforeAll(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;

  const db = getDb();
  await resetTestDb();
  await db.exec('DELETE FROM audit_log;');
  await db.exec('DELETE FROM withdrawal_sessions;');
  await db.exec('DELETE FROM spent_coins;');
  await db.exec('DELETE FROM transactions;');
  await db.exec('DELETE FROM users;');
  await db.exec('DELETE FROM bank_keys;');
  await db.exec('UPDATE bank_reserve SET total_issued=0, total_redeemed=0, reserve_balance=0 WHERE id=1;');

  const aHash = await hashPassword(ADMIN.password);
  const aUser = await createUser(ADMIN.username, aHash, ADMIN.role);
  adminToken = generateToken(aUser);

  const cHash = await hashPassword(CUSTOMER.password);
  const cUser = await createUser(CUSTOMER.username, cHash, CUSTOMER.role);
  customerToken = generateToken(cUser);

  // Seed the active bank key (needed for rotate-key test)
  await getOrGenerate();
});

beforeEach(async () => {
  const db = getDb();
  await db.exec('DELETE FROM audit_log;');
});

afterAll(async () => {
  await closeTestDb();
  server.close();
  for (const suffix of ['', '-wal', '-shm']) {

  }
});

describe('Phase 3 · /api/admin/audit + /api/admin/rotate-key (requireAdmin middleware)', () => {
  it('GET /api/admin/audit without Authorization → 401 UNAUTHORIZED', async () => {
    const res = await api('/api/admin/audit');
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('UNAUTHORIZED');
  });

  it('GET /api/admin/audit with customer token → 403 FORBIDDEN', async () => {
    const res = await api('/api/admin/audit', { token: customerToken });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('FORBIDDEN');
  });

  it('GET /api/admin/audit with admin token → 200 + paginated structure', async () => {
    // Seed 2 audit entries
    await logAction({ actor_id: 1, action: 'deposit', amount: 100 });
    await logAction({ actor_id: 2, action: 'withdraw', amount: 30 });

    const res = await api('/api/admin/audit?page=1&pageSize=10', { token: adminToken });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('entries');
    expect(res.body).toHaveProperty('total');
    expect(res.body).toHaveProperty('page');
    expect(res.body).toHaveProperty('pageSize');
    expect(res.body.total).toBe(2);
    expect(res.body.entries).toHaveLength(2);
    // Default ordering: created_at DESC, id DESC. Both seeded within the
    // same millisecond sometimes, so just check both actions are present.
    const actions = res.body.entries.map((e) => e.action).sort();
    expect(actions).toEqual(['deposit', 'withdraw']);
  });

  it('GET /api/admin/audit?action=deposit returns only deposit entries', async () => {
    await logAction({ actor_id: 1, action: 'deposit', amount: 100 });
    await logAction({ actor_id: 2, action: 'withdraw', amount: 30 });
    await logAction({ actor_id: 3, action: 'deposit', amount: 200 });

    const res = await api('/api/admin/audit?action=deposit', { token: adminToken });
    expect(res.status).toBe(200);
    expect(res.body.total).toBe(2);
    expect(res.body.entries).toHaveLength(2);
    expect(res.body.entries.every((e) => e.action === 'deposit')).toBe(true);
  });

  it('POST /api/admin/rotate-key with admin token → 200 + new key_version', async () => {
    const before = await getActiveKeyVersion();
    const res = await api('/api/admin/rotate-key', { method: 'POST', token: adminToken });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('old_version');
    expect(res.body).toHaveProperty('new_version');
    expect(res.body.old_version).toBe(before);
    expect(res.body.new_version).toBe(before + 1);

    // Active key version in DB should be incremented
    _resetCacheForTest();
    expect(await getActiveKeyVersion()).toBe(before + 1);

    // An audit log entry for the rotation should have been written (bankKeyService
    // calls logAction with action='key_rotate' inside its tx).
    const auditRow = await queryOne(
      `SELECT action, target FROM audit_log WHERE action = 'key_rotate'`,
    );
    expect(auditRow).toBeDefined();
    expect(auditRow.action).toBe('key_rotate');
  });
});
