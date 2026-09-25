// tests/transactions.test.js — M7: 账本流水 + 角色解锁闭环
//
// 验证四件事：
//   1. 取款成功 → transactions 表有一条 withdraw 流水
//   2. 收款成功 → transactions 表有一条 deposit 流水（serial 非空）
//   3. 取款取消 → transactions 表有一条 refund 流水
//   4. GET /api/transactions 返回当前用户的流水（倒序）
//   5. 角色解锁：customer 也能存 token；merchant 也能取款
//
// 复用 payment.test.js 的 mintToken 模式（完整 4-move 取款 + 解盲）。

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

import app from '../src/app.js';
import { getDb, closeDb } from '../src/models/db.js';
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

const CUSTOMER  = { username: 'alice_tx', password: 'Passw0rd!extra', role: 'customer' };
const MERCHANT  = { username: 'bob_tx',   password: 'Passw0rd!extra', role: 'merchant' };

let customerToken, merchantToken, customerId, merchantId;

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
// Phase 1: setBalance removed — direct UPDATE users.balance without updating
// bank_reserve breaks assertInvariant. Use await fundUser(id, amount) for normal
// funding; await resetBalancesAndReserve(db) in beforeEach resets all balances to 0.

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

/** 跑完整 4-move 取款，返回 { token, session_id } */
async function mintToken (token, amount = 10) {
  const denomination = amount;
  const init = await api('/api/withdraw/init', { method: 'POST', token, body: { amount, denomination } });
  expect(init.status).toBe(201);
  const { session_id, R, N } = init.body;
  const pubRes = await api('/api/bank/pubkeys');
  const publicKeyHex = pubRes.body.denominations[String(denomination)].public_key;
  const { candidates, blinders } = await clientBuildCandidates(R, amount, publicKeyHex);

  const submit = await api('/api/withdraw/submit', {
    method: 'POST', token,
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
    method: 'POST', token,
    body: { session_id, revealed },
  });
  expect(reveal.status).toBe(200);
  const sJ = hexToScalarFixed(reveal.body.s_j);
  const sPrime = unblindResponse(sJ, blinders[j].alpha);

  return {
    session_id,
    token: {
      serial: candidates[j].serial,
      amount,
      R_prime: candidates[j].R_prime,
      s_prime: scalarToHexFixed(sPrime),
      key_id: init.body.key_id,
    },
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
  await db.exec('DELETE FROM users;');
  await db.exec('DELETE FROM bank_keys;');
  // Phase 1: also reset bank_reserve singleton to 0.
  await db.exec('UPDATE bank_reserve SET total_issued=0, total_redeemed=0, reserve_balance=0 WHERE id=1;');

  const cHash = await hashPassword(CUSTOMER.password);
  const cUser = await createUser(CUSTOMER.username, cHash, CUSTOMER.role);
  customerToken = generateToken(cUser);
  customerId = cUser.id;

  const mHash = await hashPassword(MERCHANT.password);
  const mUser = await createUser(MERCHANT.username, mHash, MERCHANT.role);
  merchantToken = generateToken(mUser);
  merchantId = mUser.id;
});

beforeEach(async () => {
  // Phase 1: resetBalancesAndReserve clears protocol tables + all balances
  // to 0 + bank_reserve singleton. Then fundUser properly deposits 100 BC
  // into the customer. Merchant is NOT funded here — funding the merchant
  // would add a 'deposit' row that interferes with the deposit-stream
  // assertions in "收款成功后 transactions 表有一条 deposit 流水". Tests
  // that need merchant balance (5.2 merchant 也能取款, 5.3 完整转账闭环)
  // fund the merchant explicitly inside the test body.
  const db = getDb();
  await resetBalancesAndReserve(db);
  await fundUser(customerId, 100);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  await closeTestDb();});

// ════════════════════════════════════════════════════════════════
// 1. WITHDRAW 写流水
// ════════════════════════════════════════════════════════════════

describe('M7: withdraw 写流水', () => {
  it('取款成功后 transactions 表有一条 withdraw 流水', async () => {
    const { session_id } = await mintToken(customerToken, 10);

    const db = getDb();
    // Phase 1: filter to only 'withdraw' rows — await fundUser(customerId, 100)
    // in beforeEach also adds a 'deposit' row (counterparty='bank') that
    // is NOT a withdraw, so unfiltered rows.length would be 2.
    const rows = await db.prepare(
      `SELECT kind, amount, counterparty, session_id, note FROM transactions
       WHERE user_id = ? AND kind = 'withdraw'`,
    ).all(customerId);
    expect(rows.length).toBe(1);
    expect(rows[0].kind).toBe('withdraw');
    expect(rows[0].amount).toBe(10);
    expect(rows[0].counterparty).toBe('bank');
    expect(rows[0].session_id).toBe(session_id);
    expect(rows[0].note).toBe('取款');
  });
});

// ════════════════════════════════════════════════════════════════
// 2. DEPOSIT 写流水
// ════════════════════════════════════════════════════════════════

describe('M7: deposit 写流水', async () => {
  it('收款成功后 transactions 表有一条 deposit 流水（serial 非空）', async () => {
    const { token } = await mintToken(customerToken, 10);
    const res = await api('/api/payment', {
      method: 'POST', token: merchantToken,
      body: token,
    });
    expect(res.status).toBe(200);

    const db = getDb();
    // Phase 1: filter to only 'deposit' rows with counterparty IS NULL —
    // these are /api/payment deposits (Chaum 匿名). The fundUser deposit
    // (if any) has counterparty='bank' and is excluded.
    const rows = await db.prepare(
      `SELECT kind, amount, counterparty, serial, note FROM transactions
       WHERE user_id = ? AND kind = 'deposit' AND counterparty IS NULL`,
    ).all(merchantId);
    expect(rows.length).toBe(1);
    expect(rows[0].amount).toBe(10);
    expect(rows[0].counterparty).toBeNull(); // Chaum 匿名
    expect(rows[0].serial).not.toBeNull();   // serial 非空
    expect(rows[0].note).toBe('收款');
  });
});

// ════════════════════════════════════════════════════════════════
// 3. REFUND 写流水
// ════════════════════════════════════════════════════════════════

describe('M7: refund 写流水', async () => {
  it('取款取消后 transactions 表有一条 refund 流水', async () => {
    const init = await api('/api/withdraw/init', {
      method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 },
    });
    const cancel = await api('/api/withdraw/cancel', {
      method: 'POST', token: customerToken, body: { session_id: init.body.session_id },
    });
    expect(cancel.status).toBe(200);

    const db = getDb();
    // Phase 1: filter to only 'refund' rows — await fundUser(customerId, 100) in
    // beforeEach also adds a 'deposit' row that is NOT a refund.
    const rows = await db.prepare(
      `SELECT kind, amount, counterparty, session_id, note FROM transactions
       WHERE user_id = ? AND kind = 'refund'`,
    ).all(customerId);
    expect(rows.length).toBe(1);
    expect(rows[0].kind).toBe('refund');
    expect(rows[0].amount).toBe(10);
    expect(rows[0].counterparty).toBe('bank');
    expect(rows[0].session_id).toBe(init.body.session_id);
    expect(rows[0].note).toContain('退款');
  });
});

// ════════════════════════════════════════════════════════════════
// 4. GET /api/transactions
// ════════════════════════════════════════════════════════════════

describe('M7: GET /api/transactions', async () => {
  it('返回当前用户的流水（倒序）', async () => {
    // 先取款（withdraw 流水）
    await mintToken(customerToken, 10);
    // 再存给自己（deposit 流水，角色已解锁）
    const { token } = await mintToken(customerToken, 10);
    await api('/api/payment', { method: 'POST', token: customerToken, body: token });

    const res = await api('/api/transactions', { token: customerToken });
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.transactions)).toBe(true);
    // customer 应该有：withdraw 10 + withdraw 10 + deposit 10 = 3 条
    // （第二次 mintToken 又产生一条 withdraw 10）
    expect(res.body.transactions.length).toBeGreaterThanOrEqual(3);
    // 倒序：最新在前
    const kinds = res.body.transactions.map((t) => t.kind);
    expect(kinds[0]).toBe('deposit'); // 最后发生的是 deposit
  });

  it('未登录调用 → 401', async () => {
    const res = await api('/api/transactions');
    expect(res.status).toBe(401);
  });
});

// ════════════════════════════════════════════════════════════════
// 5. 角色解锁闭环
// ════════════════════════════════════════════════════════════════

describe('M7: 角色解锁闭环', async () => {
  it('customer 也能存 token（角色锁已解锁）', async () => {
    // customer 取款 10 → 余额 100→90
    const { token } = await mintToken(customerToken, 10);
    // customer 存给自己 → 余额 90→100
    const res = await api('/api/payment', {
      method: 'POST', token: customerToken,
      body: token,
    });
    expect(res.status).toBe(200);
    expect(res.body.deposited).toBe(10);
    expect(res.body.new_balance).toBe(100); // 回到 100
  });

  it('merchant 也能取款（角色锁已解锁）', async () => {
    // Phase 1: merchant not funded in beforeEach (would add 'deposit' row
    // interfering with deposit-stream assertions). Fund explicitly here so
    // merchant has balance=100 to withdraw 10 → 90.
    await fundUser(merchantId, 100);
    // merchant 取款 10 → 余额 100→90
    const res = await mintToken(merchantToken, 10);
    expect(res.token.amount).toBe(10);

    const db = getDb();
    const m = await db.prepare('SELECT balance FROM users WHERE id = ?').get(merchantId);
    expect(m.balance).toBe(90);

    // merchant 也有 withdraw 流水
    const rows = await db.prepare(
      `SELECT kind FROM transactions WHERE user_id = ?`,
    ).all(merchantId);
    expect(rows.some((r) => r.kind === 'withdraw')).toBe(true);
  });

  it('完整转账闭环：customer 取款 → merchant 收款 → merchant 取款 → customer 收款', async () => {
    // Phase 1: merchant not funded in beforeEach. Fund explicitly here so
    // merchant starts at 100 — needed for step 3 (withdraw 10 after receiving
    // 10 → 110→100) and for the assertions against new_balance below.
    await fundUser(merchantId, 100);
    // 1. customer 取款 10（100→90）
    const { token } = await mintToken(customerToken, 10);
    // 2. merchant 收款 10（100→110）
    const dep = await api('/api/payment', {
      method: 'POST', token: merchantToken, body: token,
    });
    expect(dep.status).toBe(200);
    expect(dep.body.new_balance).toBe(110);
    // 3. merchant 取款 10（110→100）
    const { token: token2 } = await mintToken(merchantToken, 10);
    // 4. customer 收款 10（90→100）
    const dep2 = await api('/api/payment', {
      method: 'POST', token: customerToken, body: token2,
    });
    expect(dep2.status).toBe(200);
    expect(dep2.body.new_balance).toBe(100);

    // 验证双方流水
    const custTx = await api('/api/transactions', { token: customerToken });
    const merchTx = await api('/api/transactions', { token: merchantToken });
    // customer 有：withdraw 10 + deposit 10
    const custKinds = custTx.body.transactions.map((t) => t.kind);
    expect(custKinds).toContain('withdraw');
    expect(custKinds).toContain('deposit');
    // merchant 有：deposit 10 + withdraw 10
    const merchKinds = merchTx.body.transactions.map((t) => t.kind);
    expect(merchKinds).toContain('deposit');
    expect(merchKinds).toContain('withdraw');
  });
});
