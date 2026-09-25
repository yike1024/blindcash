// tests/redeemSplit.test.js — Phase 6.2: 找零/部分取款（redeem-split）
//
// v6 §四 6.2 验收矩阵：
//   ✓ happy path: 50 BC token, split_denomination=10 → 余额+50, split_count=5
//   ✓ 100 BC token, split_denomination=5 → split_count=20
//   ✓ split_denomination=1 → split_count=amount
//   ✓ 双花：同 token 第二次调 redeem-split → 409 DOUBLE_SPEND
//   ✓ redeem 后再 redeem-split 同 token → 409 DOUBLE_SPEND
//   ✓ 非法 split_denomination (0, 3, 200) → 400 INVALID_SPLIT_DENOMINATION
//   ✓ amount 不能整除 split_denomination → 400 SPLIT_NOT_DIVISIBLE
//   ✓ 缺字段 → 400 VALIDATION_ERROR
//   ✓ 无 JWT → 401
//   ✓ 篡改 amount → 400 SIGNATURE_INVALID
//   ✓ 返回 limitations 数组（3 条，含 Chaum 找零警告 + 时间侧信道）
//   ✓ 审计日志写入
//   ✓ 流水 kind=redeem_split 写入 transactions 表
//
// 文献参考：
//   [1] Brands S. 1993. "Untraceable Off-Line Cash in Wallets with Observers".
//       Crypto'93. §3 — 钱包观察者协议。
//   [2] Chaum D. 1985. "Security Without Identification". CACM 28(10).
//       §"Privacy" — 时间侧信道对匿名集的削弱。
//   [3] Chaum D. 1982. "Blind Signatures for Untraceable Payments". Crypto'82.
//       §3 — 不可追踪支付的盲签名基础。

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

import app from '../src/app.js';
import { getDb, closeDb, queryOne } from '../src/models/db.js';
import { resetTestDb, ensureDatabaseUrl, closeTestDb } from './helpers/testDb.js';
import { hashToScalar } from '../src/crypto/server/hashToScalar.js';
import { generateBlinders, computeBlindedCommitment, unblindResponse } from '../src/crypto/client/blinding.js';
import { bytesToHex, hexToBytes } from '../src/utils/hex.js';
import { modN } from '../src/crypto/server/curve.js';
import { TOKEN_DOMAIN_TAG } from '../src/config/bank.js';
import { createUser } from '../src/services/userService.js';
import { hashPassword, generateToken } from '../src/services/authService.js';
import { fundUser, resetBalancesAndReserve } from './helpers/fundUser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
ensureDatabaseUrl();
process.env.BC_DEMO_N = '10';const server = http.createServer(app);
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

const CUSTOMER = { username: 'alice_split', password: 'Passw0rd!', role: 'customer' };
let customerToken, customerId;

// ── helpers ──

function scalarToHexFixed (s) {
  let h = s.toString(16);
  while (h.length < 64) h = '0' + h;
  return h;
}
function hexToScalarFixed (hex) {
  let v = 0n;
  for (let i = 0; i < hex.length; i++) v = (v << 4n) | BigInt(parseInt(hex[i], 16));
  return v;
}

async function clientBuildCandidates (RHexList, amount, publicKeyHex) {
  const publicKey = hexToBytes(publicKeyHex);
  const candidates = [];
  const blinders = [];
  for (let i = 0; i < RHexList.length; i++) {
    const R = hexToBytes(RHexList[i]);
    const bl = generateBlinders();
    const RPrime = computeBlindedCommitment(R, bl.alpha, bl.beta, publicKey);
    const serial = new Uint8Array(32);
    globalThis.crypto.getRandomValues(serial);
    const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, amount, publicKey);
    const e = modN(ePrime + bl.beta);
    candidates.push({
      e: scalarToHexFixed(e),
      R_prime: bytesToHex(RPrime),
      serial: bytesToHex(serial),
    });
    blinders.push({ alpha: bl.alpha, beta: bl.beta });
  }
  return { candidates, blinders };
}

/** Mint a token at the given denomination. Returns the v2 token shape. */
async function mintToken (amount, denomination = 1) {
  const init = await api('/api/withdraw/init', {
    method: 'POST', token: customerToken, body: { amount, denomination },
  });
  expect(init.status).toBe(201);
  const { session_id, R, N, key_id } = init.body;

  // Fetch pubkey for this denomination
  const pubRes = await api('/api/bank/pubkeys');
  const publicKeyHex = pubRes.body.denominations[String(denomination)].public_key;
  const { candidates, blinders } = await clientBuildCandidates(R, amount, publicKeyHex);

  const submit = await api('/api/withdraw/submit', {
    method: 'POST', token: customerToken,
    body: { session_id, candidates },
  });
  expect(submit.status).toBe(200);
  const { j } = submit.body;

  const revealed = [];
  for (let i = 0; i < N; i++) {
    if (i === j) continue;
    revealed.push({
      i,
      alpha: scalarToHexFixed(blinders[i].alpha),
      beta: scalarToHexFixed(blinders[i].beta),
    });
  }
  const reveal = await api('/api/withdraw/reveal', {
    method: 'POST', token: customerToken,
    body: { session_id, revealed },
  });
  expect(reveal.status).toBe(200);
  const sJ = hexToScalarFixed(reveal.body.s_j);
  const sPrime = unblindResponse(sJ, blinders[j].alpha);

  return {
    v: 2,
    key_id: key_id ?? reveal.body.key_id ?? 1,
    denomination,
    serial: candidates[j].serial,
    amount,
    R_prime: candidates[j].R_prime,
    s_prime: scalarToHexFixed(sPrime),
  };
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
  await db.exec('DELETE FROM audit_log;');
  await db.exec('DELETE FROM users;');
  await db.exec('DELETE FROM bank_keys;');
  await db.exec('UPDATE bank_reserve SET total_issued=0, total_redeemed=0, reserve_balance=0 WHERE id=1;');

  const cHash = await hashPassword(CUSTOMER.password);
  const cUser = await createUser(CUSTOMER.username, cHash, CUSTOMER.role);
  customerToken = generateToken(cUser);
  customerId = cUser.id;

  // Seed keys for all denominations
  // (await getOrGenerate(denom) is called lazily by initWithdrawal, but
  //  ensure they exist before tests start)
});

beforeEach(async () => {
  const db = getDb();
  await resetBalancesAndReserve(db);
  await db.exec('DELETE FROM audit_log;');
  await fundUser(customerId, 200);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  await closeTestDb();
  for (const suffix of ['', '-wal', '-shm']) {

  }
});

// ════════════════════════════════════════════════════════════════
// HAPPY PATH
// ════════════════════════════════════════════════════════════════

describe('Phase 6.2 · /api/bank/redeem-split — happy path', () => {
  it('50 BC token (denom=50), split_denomination=10 → balance+50, split_count=5', async () => {
    const tok = await mintToken(50, 50);
    // Net balance change: -50 (withdraw) + 50 (redeem-split) = 0
    // Initial 200 → 200 - 50 (withdraw) → 200 (after +50 redeem)
    const res = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 10 },
    });
    if (res.status !== 200) console.error('DEBUG happy1:', res.status, res.body);
    expect(res.status).toBe(200);
    expect(res.body.deposited).toBe(50);
    expect(res.body.new_balance).toBe(200); // 200 - 50 (withdraw) + 50 (redeem)
    expect(res.body.split_denomination).toBe(10);
    expect(res.body.split_count).toBe(5);
    expect(res.body.limitations).toHaveLength(3);
  });

  it('100 BC token (denom=100), split_denomination=5 → split_count=20', async () => {
    const tok = await mintToken(100, 100);
    const res = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 5 },
    });
    expect(res.status).toBe(200);
    expect(res.body.split_count).toBe(20);
  });

  it('10 BC token (denom=10), split_denomination=1 → split_count=10', async () => {
    const tok = await mintToken(10, 10);
    const res = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 1 },
    });
    expect(res.status).toBe(200);
    expect(res.body.split_count).toBe(10);
  });

  it('spent_coins row denomination is split_denomination (teaching-only)', async () => {
    const tok = await mintToken(50, 50);
    await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 5 },
    });
    const row = await queryOne('SELECT denomination, amount FROM spent_coins WHERE serial = ?',
      [Buffer.from(hexToBytes(tok.serial))]);
    expect(row.denomination).toBe(5); // split_denomination, not original 50
    expect(row.amount).toBe(50);
  });

  it('writes a redeem_split transaction row', async () => {
    // denomination=10 is a valid DENOMINATIONS entry; amount must equal
    // denomination (amount === denomination invariant). split_denom=5 → 2 coins.
    const tok = await mintToken(10, 10);
    await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 5 },
    });
    const tx = await queryOne(
      "SELECT kind, amount, counterparty, note FROM transactions WHERE kind = 'redeem_split' AND user_id = ? ORDER BY id DESC LIMIT 1",
      [customerId],
    );
    expect(tx).toBeDefined();
    expect(tx.amount).toBe(10);
    expect(tx.counterparty).toBe('bank');
    expect(tx.note).toContain('split into');
    expect(tx.note).toContain('2×5BC');
  });

  it('writes an audit_log entry', async () => {
    const tok = await mintToken(10, 10);
    await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 5 },
    });
    const audit = await queryOne(
      "SELECT action, amount FROM audit_log WHERE action = 'redeem_split' AND actor_id = ? ORDER BY id DESC LIMIT 1",
      [customerId],
    );
    expect(audit).toBeDefined();
    expect(audit.action).toBe('redeem_split');
    expect(audit.amount).toBe(10);
  });
});

// ════════════════════════════════════════════════════════════════
// ERROR CASES
// ════════════════════════════════════════════════════════════════

describe('Phase 6.2 · /api/bank/redeem-split — errors', async () => {
  it('no Authorization → 401', async () => {
    const res = await api('/api/bank/redeem-split', {
      method: 'POST',
      body: { serial: '00', amount: 10, R_prime: '00', s_prime: '00', split_denomination: 5 },
    });
    expect(res.status).toBe(401);
  });

  it('missing split_denomination → 400 VALIDATION_ERROR', async () => {
    const tok = await mintToken(10, 10);
    const res = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { serial: tok.serial, amount: tok.amount, R_prime: tok.R_prime, s_prime: tok.s_prime },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
  });

  it('invalid split_denomination (0, 3, 200) → 400 INVALID_SPLIT_DENOMINATION', async () => {
    const tok = await mintToken(50, 50);
    for (const bad of [0, 3, 200, -1, 1.5, '10', null]) {
      const res = await api('/api/bank/redeem-split', {
        method: 'POST', token: customerToken,
        body: { ...tok, split_denomination: bad },
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('INVALID_SPLIT_DENOMINATION');
    }
  });

  it('SPLIT_NOT_DIVISIBLE: amount=50, split_denom=100 → 400 (50 < 100)', async () => {
    const tok = await mintToken(50, 50);
    const res = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 100 }, // 50 < 100, 50 % 100 = 50 ≠ 0
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('SPLIT_NOT_DIVISIBLE');
  });

  it('tampered amount → 400 SIGNATURE_INVALID (divisible split_denom, sig fails first)', async () => {
    const tok = await mintToken(50, 50);
    // tamper amount to 55 (55 % 5 == 0 → passes divisibility check later)
    // but signature was for amount=50 → verifySig fails first
    const res = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, amount: 55, split_denomination: 5 },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('SIGNATURE_INVALID');
  });

  it('double-spend: same token twice → 200 + 409', async () => {
    const tok = await mintToken(50, 50);
    const body = { ...tok, split_denomination: 5 };
    const r1 = await api('/api/bank/redeem-split', { method: 'POST', token: customerToken, body });
    const r2 = await api('/api/bank/redeem-split', { method: 'POST', token: customerToken, body });
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(409);
    expect(r2.body.error).toBe('DOUBLE_SPEND');
  });

  it('redeem then redeem-split on same token → 200 + 409', async () => {
    const tok = await mintToken(50, 50);
    // First consume with /redeem
    const r1 = await api('/api/bank/redeem', {
      method: 'POST', token: customerToken,
      body: { serial: tok.serial, amount: tok.amount, R_prime: tok.R_prime, s_prime: tok.s_prime, key_id: tok.key_id },
    });
    expect(r1.status).toBe(200);
    // Then try redeem-split on the same token
    const r2 = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 5 },
    });
    expect(r2.status).toBe(409);
    expect(r2.body.error).toBe('DOUBLE_SPEND');
  });

  it('malformed token (serial 63 hex) → 400 MALFORMED_TOKEN', async () => {
    const tok = await mintToken(50, 50);
    const badSerial = tok.serial.slice(0, 63); // 63 chars, not 64
    const res = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, serial: badSerial, split_denomination: 5 },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('MALFORMED_TOKEN');
  });

  it('limitations include Chaum change warning + time side-channel warning', async () => {
    const tok = await mintToken(50, 50);
    const res = await api('/api/bank/redeem-split', {
      method: 'POST', token: customerToken,
      body: { ...tok, split_denomination: 5 },
    });
    const joined = res.body.limitations.join(' ');
    expect(joined).toMatch(/不是真正的 Chaum 找零|Chaum 找零/i);
    expect(joined).toMatch(/时间侧信道|side.?channel/i);
  });
});
