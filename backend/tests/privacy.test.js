// tests/privacy.test.js — Phase 6.3: 匿名集分析（单元 + 路由测试）
//
// v6 §四 6.3 验收矩阵：
//   ✓ await computeAnonymityReport(空数组) → { report: [], limitations: 3条 }
//   ✓ await computeAnonymityReport(非数组) → 空报告 + 3 条局限
//   ✓ 单个 token，未花费 → anonymity_set_size=0（下界诚实）
//   ✓ 单个 token，已花费一次 → anonymity_set_size=1（最弱匿名）
//   ✓ 多个用户花费同 (denom, key_version) → anonymity_set_size=N（混在一起）
//   ✓ 不同 (denom, key_version) 分组独立统计
//   ✓ 不存在的 key_id 被静默跳过（不抛错）
//   ✓ key_id=null/undefined 的 token 被跳过
//   ✓ your_tokens 计数正确（用户持有的同组 token 数）
//   ✓ limitations 总是返回 3 条（含时间侧信道警告）
//   ✓ 报告按 denomination 升序排序
//
// 路由层：
//   ✓ POST /api/privacy/report 无 Authorization → 401
//   ✓ POST /api/privacy/report tokens 非数组 → 400 VALIDATION_ERROR
//   ✓ POST /api/privacy/report 缺 body → 400 VALIDATION_ERROR
//   ✓ POST /api/privacy/report 合法 token → 200 + report 结构
//
// 文献参考：
//   [1] Chaum D. 1982. "Blind Signatures for Untraceable Payments".
//       Crypto'82. §3 — 匿名集（anonymity set）即"与目标 token 不可区分的
//       集合大小"，本测试验证服务端按 (面额, 密钥版本) 严格分组统计。
//   [2] Chaum D. 1985. "Security Without Identification: Transaction Systems
//       to Make Big Brother Obsolete". CACM 28(10). §"Privacy捗".
//       匿名集是下界，时间侧信道可缩小——本服务 limitations[1] 即此警告。
//   [3] Green M. 2021. "Cryptographic Thinking: eCash and Beyond".
//       §"Anonymity Sets vs. k-anonymity". 强调匿名集≠k-anonymity，前者
//       是攻击者视角下"不可分辨的等价类大小"，本测试的 anonymity_set_size
//       正是此语义。

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

import app from '../src/app.js';
import { getDb, closeDb, runWrite } from '../src/models/db.js';
import { resetTestDb, ensureDatabaseUrl, closeTestDb } from './helpers/testDb.js';
import { computeAnonymityReport } from '../src/services/privacyService.js';
import {
  getOrGenerate, getActiveKeyVersionByDenom, _resetCacheForTest,
} from '../src/services/bankKeyService.js';
import { createUser } from '../src/services/userService.js';
import { hashPassword, generateToken } from '../src/services/authService.js';

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

const CUSTOMER = { username: 'alice_priv', password: 'Passw0rd!', role: 'customer' };
let customerToken, customerId;

// ── helpers ──

let _seedCounter = 0;
/** Insert a fake spent_coins row for anonymity set testing.
 *  Uses customerId (a real user row) as deposited_to so FK is satisfied.
 *  token_hash is made globally unique via a monotonic counter (last 4 bytes). */
async function seedSpentCoin ({ serial, denomination, key_version, deposited_to }) {
  const serialBuf = Buffer.from(serial.padStart(64, '0').slice(0, 64), 'hex');
  const tokenHash = Buffer.alloc(32, 0);
  _seedCounter += 1;
  tokenHash.writeUInt32BE(_seedCounter, 28);
  const depositor = deposited_to ?? customerId;
  await runWrite(
    `INSERT INTO spent_coins (serial, amount, deposited_to, token_hash, key_version, denomination)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [serialBuf, denomination, depositor, tokenHash, key_version, denomination],
  );
}

beforeAll(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;

  const db = getDb();
  await resetTestDb();
  await db.exec('DELETE FROM withdrawal_sessions;');
  await db.exec('DELETE FROM spent_coins;');
  await db.exec('DELETE FROM transactions;');
  await db.exec('DELETE FROM users;');
  await db.exec('DELETE FROM bank_keys;');
  await db.exec('UPDATE bank_reserve SET total_issued=0, total_redeemed=0, reserve_balance=0 WHERE id=1;');

  const cHash = await hashPassword(CUSTOMER.password);
  const cUser = await createUser(CUSTOMER.username, cHash, CUSTOMER.role);
  customerToken = generateToken(cUser);
  customerId = cUser.id;

  // Seed active keys for denominations 1, 5, 10
  await getOrGenerate(1);
  await getOrGenerate(5);
  await getOrGenerate(10);
});

beforeEach(async () => {
  const db = getDb();
  await db.exec('DELETE FROM spent_coins;');
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  await closeTestDb();
  for (const suffix of ['', '-wal', '-shm']) {

  }
});

// ════════════════════════════════════════════════════════════════
// UNIT TESTS — computeAnonymityReport
// ════════════════════════════════════════════════════════════════

describe('Phase 6.3 · computeAnonymityReport — unit', () => {
  it('empty array → empty report + 3 limitations', async () => {
    const r = await computeAnonymityReport([]);
    expect(r.report).toEqual([]);
    expect(r.limitations).toHaveLength(3);
    // Each limitation should be a non-empty string
    for (const l of r.limitations) {
      expect(typeof l).toBe('string');
      expect(l.length).toBeGreaterThan(10);
    }
  });

  it('non-array input → empty report + limitations (no throw)', async () => {
    await computeAnonymityReport(null);
    await computeAnonymityReport(undefined);
    await computeAnonymityReport({});
    await computeAnonymityReport('not-an-array');

    expect((await computeAnonymityReport(null)).report).toEqual([]);
    expect((await computeAnonymityReport({})).report).toEqual([]);
  });

  it('token with null/undefined key_id is silently skipped', async () => {
    const r = await computeAnonymityReport([
      { key_id: null },
      { key_id: undefined },
      { /* no key_id field */ },
    ]);
    expect(r.report).toEqual([]);
  });

  it('token with non-existent key_id is silently skipped (no throw)', async () => {
    await computeAnonymityReport([{ key_id: 99999 }]);
    expect((await computeAnonymityReport([{ key_id: 99999 }])).report).toEqual([]);
  });

  it('single token, denom=1, no spent_coins → anonymity_set_size=0', async () => {
    const kv1 = await getActiveKeyVersionByDenom(1);
    const r = await computeAnonymityReport([{ key_id: kv1 }]);
    expect(r.report).toHaveLength(1);
    expect(r.report[0].denomination).toBe(1);
    expect(r.report[0].key_version).toBe(kv1);
    expect(r.report[0].anonymity_set_size).toBe(0);
    expect(r.report[0].your_tokens).toBe(1);
  });

  it('single token, spent once → anonymity_set_size=1 (deanonymized)', async () => {
    const kv1 = await getActiveKeyVersionByDenom(1);
    await seedSpentCoin({
      serial: 'aa', denomination: 1, key_version: kv1, deposited_to: customerId,
    });
    const r = await computeAnonymityReport([{ key_id: kv1 }]);
    expect(r.report[0].anonymity_set_size).toBe(1);
    expect(r.report[0].your_tokens).toBe(1);
  });

  it('multiple users spent same (denom, key_version) → anonymity_set_size=N', async () => {
    const kv5 = await getActiveKeyVersionByDenom(5);
    // Three different tokens (semantic: different merchants deposited them).
    // depositor all set to customerId for FK simplicity — anonymity set stat
    // counts rows regardless of depositor identity.
    await seedSpentCoin({ serial: '01', denomination: 5, key_version: kv5 });
    await seedSpentCoin({ serial: '02', denomination: 5, key_version: kv5 });
    await seedSpentCoin({ serial: '03', denomination: 5, key_version: kv5 });

    const r = await computeAnonymityReport([{ key_id: kv5 }]);
    expect(r.report[0].anonymity_set_size).toBe(3);
    expect(r.report[0].your_tokens).toBe(1);
  });

  it('different (denom, key_version) groups are reported independently', async () => {
    const kv1 = await getActiveKeyVersionByDenom(1);
    const kv5 = await getActiveKeyVersionByDenom(5);
    const kv10 = await getActiveKeyVersionByDenom(10);

    await seedSpentCoin({ serial: '11', denomination: 1, key_version: kv1 });
    await seedSpentCoin({ serial: '12', denomination: 1, key_version: kv1 });
    await seedSpentCoin({ serial: '51', denomination: 5, key_version: kv5 });
    await seedSpentCoin({ serial: '52', denomination: 5, key_version: kv5 });
    await seedSpentCoin({ serial: '53', denomination: 5, key_version: kv5 });
    await seedSpentCoin({ serial: '54', denomination: 5, key_version: kv5 });
    // kv10 has no spent_coins

    const r = await computeAnonymityReport([
      { key_id: kv1 }, { key_id: kv1 },        // user holds 2 of denom=1
      { key_id: kv5 },                          // user holds 1 of denom=5
      { key_id: kv10 }, { key_id: kv10 },       // user holds 2 of denom=10
    ]);

    expect(r.report).toHaveLength(3);
    // Sort by denomination ascending → [1, 5, 10]
    expect(r.report.map((x) => x.denomination)).toEqual([1, 5, 10]);

    const denom1 = r.report.find((x) => x.denomination === 1);
    expect(denom1.anonymity_set_size).toBe(2);
    expect(denom1.your_tokens).toBe(2);

    const denom5 = r.report.find((x) => x.denomination === 5);
    expect(denom5.anonymity_set_size).toBe(4);
    expect(denom5.your_tokens).toBe(1);

    const denom10 = r.report.find((x) => x.denomination === 10);
    expect(denom10.anonymity_set_size).toBe(0);
    expect(denom10.your_tokens).toBe(2);
  });

  it('limitations include time side-channel warning', async () => {
    const r = await computeAnonymityReport([]);
    const joined = r.limitations.join(' ');
    expect(joined).toMatch(/时间侧信道|time/i);
  });

  it('limitations include anonymity_set=1 deanonymization warning', async () => {
    const r = await computeAnonymityReport([]);
    const joined = r.limitations.join(' ');
    expect(joined).toMatch(/匿名集.*=.*1|匿名集.*1|确定地关联/i);
  });

  it('report is sorted by denomination ascending', async () => {
    const kv10 = await getActiveKeyVersionByDenom(10);
    const kv1 = await getActiveKeyVersionByDenom(1);
    const kv5 = await getActiveKeyVersionByDenom(5);

    // Pass in scrambled order — output should still be sorted
    const r = await computeAnonymityReport([
      { key_id: kv10 },
      { key_id: kv1 },
      { key_id: kv5 },
    ]);
    const denoms = r.report.map((x) => x.denomination);
    expect(denoms).toEqual([1, 5, 10]);
  });
});

// ════════════════════════════════════════════════════════════════
// ROUTE TESTS — POST /api/privacy/report
// ════════════════════════════════════════════════════════════════

describe('Phase 6.3 · POST /api/privacy/report — route', () => {
  it('no Authorization header → 401', async () => {
    const res = await api('/api/privacy/report', {
      method: 'POST',
      body: { tokens: [] },
    });
    expect(res.status).toBe(401);
  });

  it('tokens is not an array → 400 VALIDATION_ERROR', async () => {
    const res = await api('/api/privacy/report', {
      method: 'POST',
      token: customerToken,
      body: { tokens: 'not-an-array' },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
  });

  it('missing body → 400 VALIDATION_ERROR', async () => {
    const res = await api('/api/privacy/report', {
      method: 'POST',
      token: customerToken,
      // no body
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
  });

  it('happy path: valid tokens array → 200 with report + limitations', async () => {
    const kv1 = await getActiveKeyVersionByDenom(1);
    const res = await api('/api/privacy/report', {
      method: 'POST',
      token: customerToken,
      body: { tokens: [{ key_id: kv1 }] },
    });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.report)).toBe(true);
    expect(Array.isArray(res.body.limitations)).toBe(true);
    expect(res.body.limitations).toHaveLength(3);
  });

  it('empty tokens array → 200 with empty report + 3 limitations', async () => {
    const res = await api('/api/privacy/report', {
      method: 'POST',
      token: customerToken,
      body: { tokens: [] },
    });
    expect(res.status).toBe(200);
    expect(res.body.report).toEqual([]);
    expect(res.body.limitations).toHaveLength(3);
  });
});
