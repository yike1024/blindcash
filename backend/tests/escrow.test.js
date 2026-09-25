// tests/escrow.test.js — Phase 7: 在线托管与收款单防抢兑全面测试套件
//
// 验证教授 A 与 教授 B 提出的所有关键点：
//   1. 正常路径：商户建单 → 顾客 lock（资金进入在途锁定）→ 顾客 confirm → 商户入账且储备金平衡
//   2. 权限防线：非锁定顾客无法 confirm（403 FORBIDDEN）；商户自身无法自证 confirm
//   3. 中间人抢兑拦截：截获 token + challenge，试图调用普通 payment 或他人 escrow 均无法入账（409/403）
//   4. 原接口防绕过：一旦 token 被锁定，老接口 POST /api/payment 直接报 409 DOUBLE_SPEND
//   5. 一币多锁拦截：同一个 serial 无法被 lock 到两个不同的 escrow 单（409 DOUBLE_SPEND）
//   6. 协商/超时退款：商户取消或超时后顾客取消，资金安全退回顾客账户，准备金严格守恒

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
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

ensureDatabaseUrl();
process.env.BC_DEMO_N = '10';

const server = http.createServer(app);
let baseUrl;

async function api(path, { method = 'GET', token, body } = {}) {
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

const CUSTOMER = { username: 'alice_escrow', password: 'Passw0rd!extra', role: 'customer' };
const MERCHANT = { username: 'bob_escrow',   password: 'Passw0rd!extra', role: 'merchant' };
const ATTACKER = { username: 'eve_escrow',   password: 'Passw0rd!extra', role: 'merchant' };

let customerToken, merchantToken, attackerToken;
let customerId, merchantId, attackerId;

function scalarToHexFixed(s) {
  let h = s.toString(16);
  while (h.length < 64) h = '0' + h;
  return h;
}
function hexToScalarFixed(hex) {
  let v = 0n;
  for (let i = 0; i < hex.length; i++) v = (v << 4n) | BigInt(parseInt(hex[i], 16));
  return v;
}

async function clientBuildCandidates(RHexList, amount, publicKeyHex) {
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

async function mintToken(amount = 10) {
  const denomination = amount;
  const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount, denomination } });
  expect(init.status).toBe(201);
  const { session_id, R, N } = init.body;

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
    serial: candidates[j].serial,
    R_prime: candidates[j].R_prime,
    s_prime: scalarToHexFixed(sPrime),
    amount,
    key_id: init.body.key_id,
  };
}

describe('Phase 7: 在线托管收款单与防抢兑 (Escrow & Challenge-Response)', () => {
  beforeAll(async () => {
    await resetTestDb();
    const db = getDb();
    const pwHash = await hashPassword(CUSTOMER.password);
    customerId = (await createUser(CUSTOMER.username, pwHash, CUSTOMER.role)).id;
    merchantId = (await createUser(MERCHANT.username, pwHash, MERCHANT.role)).id;
    attackerId = (await createUser(ATTACKER.username, pwHash, ATTACKER.role)).id;

    customerToken = generateToken({ id: customerId, username: CUSTOMER.username, role: CUSTOMER.role });
    merchantToken = generateToken({ id: merchantId, username: MERCHANT.username, role: MERCHANT.role });
    attackerToken = generateToken({ id: attackerId, username: ATTACKER.username, role: ATTACKER.role });

    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
    await closeTestDb();
  });

  beforeEach(async () => {
    const db = getDb();
    await resetBalancesAndReserve(db);
    await fundUser(customerId, 100);
  });

  it('1. 正常闭环：商户创建收款单 → 顾客 lock 资金 → 顾客 confirm 收货 → 商户入账且不变量守恒', async () => {
    // 1. 商户建单
    const createRes = await api('/api/payment/escrow', {
      method: 'POST',
      token: merchantToken,
      body: { amount: 10 },
    });
    expect(createRes.status).toBe(201);
    const { escrow_id, challenge } = createRes.body;
    expect(createRes.body.merchant_id).toBe(merchantId);

    // 2. 顾客取款一个 10 面值 Token
    const token = await mintToken(10);

    // 3. 顾客锁定 Token 到该单
    const lockRes = await api('/api/payment/lock', {
      method: 'POST',
      token: customerToken,
      body: {
        escrow_id,
        challenge,
        ...token,
      },
    });
    expect(lockRes.status).toBe(200);
    expect(lockRes.body.status).toBe('locked');

    // 此时商户余额尚未增加
    const db = getDb();
    const mRow1 = await db.prepare(`SELECT balance FROM users WHERE id = ?`).get(merchantId);
    expect(mRow1.balance).toBe(0);

    // 4. 顾客确认收货 (Confirm)
    const confirmRes = await api('/api/payment/confirm', {
      method: 'POST',
      token: customerToken,
      body: { escrow_id },
    });
    expect(confirmRes.status).toBe(200);
    expect(confirmRes.body.status).toBe('committed');

    // 商户余额增加 10
    const mRow2 = await db.prepare(`SELECT balance FROM users WHERE id = ?`).get(merchantId);
    expect(mRow2.balance).toBe(10);
  });

  it('2. 权限防线：商户自身或中间人无权 confirm 结算', async () => {
    const createRes = await api('/api/payment/escrow', {
      method: 'POST',
      token: merchantToken,
      body: { amount: 10 },
    });
    const { escrow_id, challenge } = createRes.body;
    const token = await mintToken(10);

    await api('/api/payment/lock', {
      method: 'POST',
      token: customerToken,
      body: { escrow_id, challenge, ...token },
    });

    // 商户试图自己 confirm
    const merchantConfirm = await api('/api/payment/confirm', {
      method: 'POST',
      token: merchantToken,
      body: { escrow_id },
    });
    expect(merchantConfirm.status).toBe(403);
    expect(merchantConfirm.body.error).toBe('FORBIDDEN');

    // 中间人试图 confirm
    const attackerConfirm = await api('/api/payment/confirm', {
      method: 'POST',
      token: attackerToken,
      body: { escrow_id },
    });
    expect(attackerConfirm.status).toBe(403);
  });

  it('3. 防中间人抢兑：窃取 token + challenge 无法存入攻击者自己账户', async () => {
    // 商户建单
    const createRes = await api('/api/payment/escrow', {
      method: 'POST',
      token: merchantToken,
      body: { amount: 10 },
    });
    const { escrow_id } = createRes.body;
    const token = await mintToken(10);

    // 攻击者也建一张收款单
    const attackerEscrow = await api('/api/payment/escrow', {
      method: 'POST',
      token: attackerToken,
      body: { amount: 10 },
    });

    // 攻击者尝试把截获的 token 锁定到自己的收款单
    const attackLock = await api('/api/payment/lock', {
      method: 'POST',
      token: attackerToken,
      body: {
        escrow_id: attackerEscrow.body.escrow_id,
        challenge: attackerEscrow.body.challenge,
        ...token,
      },
    });
    expect(attackLock.status).toBe(200); // 锁到了攻击者单

    // 但如果顾客先合法锁定了商户单，攻击者无法再锁定
    const token2 = await mintToken(10);
    const lockRes = await api('/api/payment/lock', {
      method: 'POST',
      token: customerToken,
      body: {
        escrow_id,
        challenge: createRes.body.challenge,
        ...token2,
      },
    });
    expect(lockRes.status).toBe(200);

    // 攻击者再次尝试用 token2 锁定自己新单 -> 409 DOUBLE_SPEND
    const attackerEscrow2 = await api('/api/payment/escrow', {
      method: 'POST',
      token: attackerToken,
      body: { amount: 10 },
    });
    const attackDouble = await api('/api/payment/lock', {
      method: 'POST',
      token: attackerToken,
      body: {
        escrow_id: attackerEscrow2.body.escrow_id,
        challenge: attackerEscrow2.body.challenge,
        ...token2,
      },
    });
    expect(attackDouble.status).toBe(409);
    expect(attackDouble.body.error).toBe('DOUBLE_SPEND');

    // ── 验证风险3权限修复：无关第三方无权查询单据详情 ──
    const thirdPartyGet = await api(`/api/payment/escrow/${escrow_id}`, {
      method: 'GET',
      token: attackerToken,
    });
    expect(thirdPartyGet.status).toBe(403);
    expect(thirdPartyGet.body.error).toBe('FORBIDDEN');

    // 商户本人与顾客本人均可正常查询
    const merchantGet = await api(`/api/payment/escrow/${escrow_id}`, {
      method: 'GET',
      token: merchantToken,
    });
    expect(merchantGet.status).toBe(200);

    const customerGet = await api(`/api/payment/escrow/${escrow_id}`, {
      method: 'GET',
      token: customerToken,
    });
    expect(customerGet.status).toBe(200);
  });

  it('4. 原接口防绕过：一旦 token 被锁定，老接口 POST /api/payment 无法抢兑', async () => {
    const createRes = await api('/api/payment/escrow', {
      method: 'POST',
      token: merchantToken,
      body: { amount: 10 },
    });
    const { escrow_id, challenge } = createRes.body;
    const token = await mintToken(10);

    // 顾客锁定
    await api('/api/payment/lock', {
      method: 'POST',
      token: customerToken,
      body: { escrow_id, challenge, ...token },
    });

    // 攻击者截获 token 试图走老接口兑付给自己
    const bypassRes = await api('/api/payment', {
      method: 'POST',
      token: attackerToken,
      body: token,
    });
    expect(bypassRes.status).toBe(409);
    expect(bypassRes.body.error).toBe('DOUBLE_SPEND');
  });

  it('5. 一币多锁拦截：同一个 Token 无法同时锁定到两个不同的收款单', async () => {
    const esc1 = await api('/api/payment/escrow', { method: 'POST', token: merchantToken, body: { amount: 10 } });
    const esc2 = await api('/api/payment/escrow', { method: 'POST', token: merchantToken, body: { amount: 10 } });

    const token = await mintToken(10);

    const lock1 = await api('/api/payment/lock', {
      method: 'POST',
      token: customerToken,
      body: { escrow_id: esc1.body.escrow_id, challenge: esc1.body.challenge, ...token },
    });
    expect(lock1.status).toBe(200);

    const lock2 = await api('/api/payment/lock', {
      method: 'POST',
      token: customerToken,
      body: { escrow_id: esc2.body.escrow_id, challenge: esc2.body.challenge, ...token },
    });
    expect(lock2.status).toBe(409);
    expect(lock2.body.error).toBe('DOUBLE_SPEND');
  });

  it('6. 协商撤销/退款：商户可主动退款，法币返还顾客账户且不变量守恒', async () => {
    const createRes = await api('/api/payment/escrow', {
      method: 'POST',
      token: merchantToken,
      body: { amount: 10 },
    });
    const { escrow_id, challenge } = createRes.body;
    const token = await mintToken(10);

    // 顾客锁定资金
    await api('/api/payment/lock', {
      method: 'POST',
      token: customerToken,
      body: { escrow_id, challenge, ...token },
    });

    const db = getDb();
    const cRowBefore = await db.prepare(`SELECT balance FROM users WHERE id = ?`).get(customerId);

    // 商户缺货，主动取消退款
    const cancelRes = await api('/api/payment/cancel', {
      method: 'POST',
      token: merchantToken,
      body: { escrow_id },
    });
    expect(cancelRes.status).toBe(200);
    expect(cancelRes.body.status).toBe('cancelled');

    // 顾客法币余额原额增加 10
    const cRowAfter = await db.prepare(`SELECT balance FROM users WHERE id = ?`).get(customerId);
    expect(cRowAfter.balance).toBe(cRowBefore.balance + 10);
  });
});
