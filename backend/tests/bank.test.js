// tests/bank.test.js — Phase 1: bank service + /api/bank routes (≥15 cases)
//
// v5 §三 1.2 + 1.3 落地测试矩阵:
//   ✓ GET /api/bank/pubkey (no auth, returns {public_key, key_id:1})     [2 cases]
//   ✓ POST /api/bank/deposit (JWT, validates amount, credits balance)     [6 cases]
//   ✓ bankService.deposit service-layer (INVALID_AMOUNT / LIMIT / USER)   [5 cases]
//   ✓ POST /api/bank/redeem (JWT, token v2 with key_id, double-spend 409) [5 cases]
//
// Test strategy: persistent http.createServer(app) on a random port; fetch()
// reuses it (avoids Windows ENOBUFS). Tokens for the redeem test are minted
// via the full M4 4-move withdrawal flow against the customer, then POSTed
// to /api/bank/redeem (which routes through processPayment internally).

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

import app from '../src/app.js';
import { initSchema, getDb, closeDb, queryOne } from '../src/models/db.js';
import { hashToScalar } from '../src/crypto/server/hashToScalar.js';
import { generateBlinders, computeBlindedCommitment, unblindResponse } from '../src/crypto/client/blinding.js';
import { bytesToHex, hexToBytes } from '../src/utils/hex.js';
import { modN } from '../src/crypto/server/curve.js';
import { TOKEN_DOMAIN_TAG } from '../src/config/bank.js';
import { createUser } from '../src/services/userService.js';
import { hashPassword, generateToken } from '../src/services/authService.js';
import {
  deposit,
  BankServiceError,
  MAX_DEPOSIT_PER_TX,
  MAX_DEPOSIT_PER_DAY,
} from '../src/services/bankService.js';
import { fundUser, resetBalancesAndReserve } from './helpers/fundUser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_PATH = join(__dirname, '..', 'data', 'test-p1-bank.db');
process.env.BC_DB_PATH = TEST_DB_PATH;
process.env.BC_DEMO_N = '10';

initSchema();

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

const CUSTOMER = { username: 'alice_bank', password: 'Passw0rd!extra', role: 'customer' };
let customerToken, customerId;

// ── 4-move withdrawal helpers (mirrors payment.test.js) ──

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

function clientBuildCandidates(RHexList, amount, publicKeyHex) {
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

/** Run full 4-move withdrawal as the customer; return the unblinded token. */
async function mintToken(amount = 30) {
  const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount } });
  expect(init.status).toBe(201);
  const { session_id, R, N } = init.body;
  const pub = await api('/api/bank/pubkey');
  const publicKeyHex = pub.body.public_key;
  const keyId = pub.body.key_id;
  const { candidates, blinders } = clientBuildCandidates(R, amount, publicKeyHex);

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
    token: {
      serial: candidates[j].serial,
      amount,
      R_prime: candidates[j].R_prime,
      s_prime: scalarToHexFixed(sPrime),
      // v5 §三 1.7 token v2: key_id from /api/bank/pubkey.
      key_id: keyId,
    },
  };
}

beforeAll(async () => {
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;

  const db = getDb();
  db.exec('DELETE FROM withdrawal_sessions;');
  db.exec('DELETE FROM spent_coins;');
  db.exec('DELETE FROM transactions;');
  db.exec('DELETE FROM users;');
  db.exec('DELETE FROM bank_keys;');
  db.exec('UPDATE bank_reserve SET total_issued=0, total_redeemed=0, reserve_balance=0 WHERE id=1;');

  const cHash = await hashPassword(CUSTOMER.password);
  const cUser = createUser(CUSTOMER.username, cHash, CUSTOMER.role);
  customerToken = generateToken(cUser);
  customerId = cUser.id;
});

beforeEach(() => {
  const db = getDb();
  resetBalancesAndReserve(db);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  closeDb();
  rmSync(TEST_DB_PATH, { force: true });
});

// ════════════════════════════════════════════════════════════════
// 1. GET /api/bank/pubkey (no auth, returns key_id:1)
// ════════════════════════════════════════════════════════════════

describe('Phase 1 · GET /api/bank/pubkey', () => {
  it('returns 200 + {public_key, encoding, byte_length, key_id:1} without auth', async () => {
    const res = await api('/api/bank/pubkey');
    expect(res.status).toBe(200);
    expect(res.body.public_key).toMatch(/^(02|03)[0-9a-f]{64}$/);
    expect(res.body.encoding).toBe('secp256k1-compressed');
    expect(res.body.byte_length).toBe(33);
    // Phase 1 token v2 schema: key_id is always 1 (single bank key).
    expect(res.body.key_id).toBe(1);
  });

  it('does NOT require authentication (no Authorization header → 200 not 401)', async () => {
    const res = await api('/api/bank/pubkey');
    expect(res.status).not.toBe(401);
    expect(res.status).toBe(200);
  });
});

// ════════════════════════════════════════════════════════════════
// 2. bankService.deposit service-layer tests
// ════════════════════════════════════════════════════════════════

describe('Phase 1 · bankService.deposit (service layer)', () => {
  it('happy path: deposit 100 returns {deposited, new_balance, daily_total}', () => {
    const result = deposit({ user_id: customerId, amount: 100, ip: '127.0.0.1' });
    expect(result.deposited).toBe(100);
    expect(result.new_balance).toBe(100);
    expect(result.daily_total).toBe(100);

    // bank_reserve should have been updated.
    const r = queryOne(
      'SELECT reserve_balance, total_issued, total_redeemed FROM bank_reserve WHERE id = 1',
    );
    expect(r.reserve_balance).toBe(100);
    expect(r.total_issued).toBe(0);
    expect(r.total_redeemed).toBe(0);

    // A 'deposit' transaction row should have been written.
    const tx = queryOne(
      `SELECT kind, amount, counterparty FROM transactions
        WHERE user_id = ? AND kind = 'deposit'`,
      [customerId],
    );
    expect(tx.kind).toBe('deposit');
    expect(tx.amount).toBe(100);
    expect(tx.counterparty).toBe('bank');
  });

  it('INVALID_AMOUNT: amount=0 throws BankServiceError(400)', () => {
    expect(() => deposit({ user_id: customerId, amount: 0 }))
      .toThrow(BankServiceError);
    let caught = null;
    try { deposit({ user_id: customerId, amount: 0 }); } catch (e) { caught = e; }
    expect(caught.status).toBe(400);
    expect(caught.code).toBe('INVALID_AMOUNT');
  });

  it('INVALID_AMOUNT: amount=-50 throws BankServiceError(400)', () => {
    expect(() => deposit({ user_id: customerId, amount: -50 }))
      .toThrow(BankServiceError);
    let caught = null;
    try { deposit({ user_id: customerId, amount: -50 }); } catch (e) { caught = e; }
    expect(caught.status).toBe(400);
    expect(caught.code).toBe('INVALID_AMOUNT');
  });

  it('INVALID_AMOUNT: amount=1.5 (non-integer) throws BankServiceError(400)', () => {
    expect(() => deposit({ user_id: customerId, amount: 1.5 }))
      .toThrow(BankServiceError);
  });

  it('DEPOSIT_LIMIT_EXCEEDED: amount > MAX_DEPOSIT_PER_TX throws 400', () => {
    const tooMuch = MAX_DEPOSIT_PER_TX + 1;
    expect(() => deposit({ user_id: customerId, amount: tooMuch }))
      .toThrow(BankServiceError);
    let caught = null;
    try { deposit({ user_id: customerId, amount: tooMuch }); } catch (e) { caught = e; }
    expect(caught.status).toBe(400);
    expect(caught.code).toBe('DEPOSIT_LIMIT_EXCEEDED');
  });

  it('USER_NOT_FOUND: deposit to non-existent user throws BankServiceError(404)', () => {
    // Id 999999 doesn't exist; the UPDATE inside runImmediateTx will affect 0 rows,
    // which the service maps to USER_NOT_FOUND.
    expect(() => deposit({ user_id: 999999, amount: 50 }))
      .toThrow(BankServiceError);
    let caught = null;
    try { deposit({ user_id: 999999, amount: 50 }); } catch (e) { caught = e; }
    expect(caught.status).toBe(404);
    expect(caught.code).toBe('USER_NOT_FOUND');
  });
});

// ════════════════════════════════════════════════════════════════
// 3. POST /api/bank/deposit route (HTTP + JWT)
// ════════════════════════════════════════════════════════════════

describe('Phase 1 · POST /api/bank/deposit (route layer)', () => {
  it('without JWT → 401', async () => {
    const res = await api('/api/bank/deposit', { method: 'POST', body: { amount: 100 } });
    expect(res.status).toBe(401);
  });

  it('with JWT + {amount:100} → 200, returns {deposited, new_balance, daily_total}', async () => {
    const res = await api('/api/bank/deposit', {
      method: 'POST', token: customerToken, body: { amount: 100 },
    });
    expect(res.status).toBe(200);
    expect(res.body.deposited).toBe(100);
    expect(res.body.new_balance).toBe(100);
    expect(res.body.daily_total).toBe(100);

    // Confirm the user's balance is actually 100 in the DB.
    const u = queryOne('SELECT balance FROM users WHERE id = ?', [customerId]);
    expect(u.balance).toBe(100);
  });

  it('with JWT but missing amount → 400 VALIDATION_ERROR', async () => {
    const res = await api('/api/bank/deposit', { method: 'POST', token: customerToken, body: {} });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
  });

  it('with JWT + {amount:-1} → 400 INVALID_AMOUNT', async () => {
    const res = await api('/api/bank/deposit', {
      method: 'POST', token: customerToken, body: { amount: -1 },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('INVALID_AMOUNT');
  });

  it('with JWT + {amount:1001} → 400 DEPOSIT_LIMIT_EXCEEDED', async () => {
    const res = await api('/api/bank/deposit', {
      method: 'POST', token: customerToken, body: { amount: MAX_DEPOSIT_PER_TX + 1 },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('DEPOSIT_LIMIT_EXCEEDED');
  });

  it('two deposits in the same 24h window accumulate daily_total correctly', async () => {
    // First deposit 100 → daily_total=100.
    const r1 = await api('/api/bank/deposit', {
      method: 'POST', token: customerToken, body: { amount: 100 },
    });
    expect(r1.status).toBe(200);
    expect(r1.body.daily_total).toBe(100);
    expect(r1.body.new_balance).toBe(100);

    // Second deposit 50 → daily_total=150.
    const r2 = await api('/api/bank/deposit', {
      method: 'POST', token: customerToken, body: { amount: 50 },
    });
    expect(r2.status).toBe(200);
    expect(r2.body.daily_total).toBe(150);
    expect(r2.body.new_balance).toBe(150);
  });
});

// ════════════════════════════════════════════════════════════════
// 4. POST /api/bank/redeem route (HTTP + JWT, token v2 with key_id)
// ════════════════════════════════════════════════════════════════

describe('Phase 1 · POST /api/bank/redeem (route layer)', () => {
  it('without JWT → 401', async () => {
    const res = await api('/api/bank/redeem', {
      method: 'POST', body: { serial: 'x', amount: 30, R_prime: 'y', s_prime: 'z' },
    });
    expect(res.status).toBe(401);
  });

  it('with JWT but missing fields → 400 VALIDATION_ERROR', async () => {
    const res = await api('/api/bank/redeem', {
      method: 'POST', token: customerToken, body: { serial: 'x' },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
  });

  it('happy path: redeem own token (v2 with key_id) → 200, balance credited', async () => {
    // Fund customer 100, withdraw 30 (→ balance 70), redeem own token (→ balance 100).
    fundUser(customerId, 100);
    const { token } = await mintToken(30);

    // Sanity: token includes key_id (v2 schema).
    expect(token.key_id).toBe(1);

    const res = await api('/api/bank/redeem', {
      method: 'POST', token: customerToken, body: token,
    });
    expect(res.status).toBe(200);
    expect(res.body.deposited).toBe(30);
    // customer balance: 100 - 30 (withdraw) + 30 (redeem) = 100
    expect(res.body.new_balance).toBe(100);

    // bank_reserve.total_redeemed should have been bumped by 30.
    const r = queryOne(
      'SELECT total_issued, total_redeemed, reserve_balance FROM bank_reserve WHERE id = 1',
    );
    expect(r.total_issued).toBe(30);
    expect(r.total_redeemed).toBe(30);
    expect(r.reserve_balance).toBe(100);
  });

  it('redeem without key_id still works (legacy token fallback to active key)', async () => {
    // Phase 1 single key: key_id is optional in processPayment — falls back
    // to getActivePublicKey(). This proves the route accepts old-style tokens.
    fundUser(customerId, 100);
    const { token } = await mintToken(20);
    // Strip key_id — emulate a legacy token.
    const { key_id, ...legacyToken } = token;
    expect(key_id).toBe(1);

    const res = await api('/api/bank/redeem', {
      method: 'POST', token: customerToken, body: legacyToken,
    });
    expect(res.status).toBe(200);
    expect(res.body.deposited).toBe(20);
    expect(res.body.new_balance).toBe(100); // 100 - 20 + 20 = 100
  });

  it('double-redeem same token → 409 DOUBLE_SPEND', async () => {
    fundUser(customerId, 100);
    const { token } = await mintToken(25);

    // First redeem succeeds.
    const r1 = await api('/api/bank/redeem', {
      method: 'POST', token: customerToken, body: token,
    });
    expect(r1.status).toBe(200);
    expect(r1.body.deposited).toBe(25);

    // Second redeem with the same serial → 409.
    const r2 = await api('/api/bank/redeem', {
      method: 'POST', token: customerToken, body: token,
    });
    expect(r2.status).toBe(409);
    expect(r2.body.error).toBe('DOUBLE_SPEND');
  });
});
