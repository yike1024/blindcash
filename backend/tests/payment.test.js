// tests/payment.test.js — M5: payment + double-spend detection (≥12 cases)
//
// v3 §四-4 + professor's M5 acceptance checklist:
//   ✓ happy path: customer withdraw 30 → merchant deposits → merchant=30, customer=70
//   ✓ concurrent double-spend: two merchants concurrent same token → 200 + 409 (H3)
//   ✓ same merchant retry → 409 (H3 retry semantics)
//   ✓ malformed token ×4: serial 63hex / R' prefix 04 / s' 63hex / amount=0 → 400 (H1)
//   ✓ tampered amount → SIGNATURE_INVALID 400
//   ✓ customer calls /api/payment → 403 (ISOLATION §一-2 role guard)
//   ✓ initial balance: register customer → balance=0, then await fundUser(100) via deposit
//   ✓ missing field → 400 VALIDATION_ERROR
//   ✓ unauthenticated call → 401
//
// Test strategy: persistent http.createServer(app) on a random port; fetch()
// reuses it (avoids Windows ENOBUFS). Tokens are obtained by running the full
// M4 4-move withdrawal flow against the customer, then handing the unblinded
// (serial, amount, R', s') to the merchant for /api/payment.

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

import app from '../src/app.js';
import { getDb, closeDb } from '../src/models/db.js';
import { resetTestDb, ensureDatabaseUrl, closeTestDb } from './helpers/testDb.js';
import { hashToScalar } from '../src/crypto/server/hashToScalar.js';
import { verifySig } from '../src/crypto/server/schnorrBlind.js';
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

/** fetch wrapper returning { status, body } for concise test assertions. */
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

const CUSTOMER  = { username: 'alice', password: 'Passw0rd!extra', role: 'customer' };
const MERCHANT1 = { username: 'bob1',   password: 'Passw0rd!extra', role: 'merchant' };
const MERCHANT2 = { username: 'bob2',   password: 'Passw0rd!extra', role: 'merchant' };

let customerToken, merchant1Token, merchant2Token, customerId, merchant1Id, merchant2Id;

// ── helpers (mirrors withdrawal.test.js so 4-move token minting is identical) ──

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

// Phase 1: setBalance removed — direct UPDATE users.balance without
// updating bank_reserve breaks assertInvariant. Use await fundUser(id, amount)
// for normal funding; await resetBalancesAndReserve(db) in beforeEach already
// resets all balances to 0 (so the merchant=0 case is covered).

/**
 * Build N blinded candidates from bank R_i list (mirrors withdrawal.test.js
 * clientBuildCandidates so the token produced is byte-for-byte identical to
 * what the browser would produce via crypto/client/blinding.js).
 */
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

/**
 * Run the full M4 4-move withdrawal flow and return the unblinded token in
 * the EXACT hex form /api/payment expects:
 *   { serialHex, amount, R_primeHex, s_primeHex }
 * plus the bigint/bytes intermediates for tamper tests.
 */
async function mintToken (amount = 10) {
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
    serialHex:   candidates[j].serial,
    R_primeHex:  candidates[j].R_prime,
    s_primeHex:  scalarToHexFixed(sPrime),
    amount,
    keyId:       init.body.key_id,
    // bigint/bytes forms for tamper tests
    sPrime,
    RPrimeBytes: hexToBytes(candidates[j].R_prime),
    serialBytes: hexToBytes(candidates[j].serial),
    publicKeyHex,
    publicKey:   hexToBytes(publicKeyHex),
  };
}

// ── setup ──

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

  // create users via service layer. Phase 1: customer.balance=0 on register.
  const cHash = await hashPassword(CUSTOMER.password);
  const cUser = await createUser(CUSTOMER.username, cHash, CUSTOMER.role);
  customerToken = generateToken(cUser);
  customerId = cUser.id;

  const m1Hash = await hashPassword(MERCHANT1.password);
  const m1User = await createUser(MERCHANT1.username, m1Hash, MERCHANT1.role);
  merchant1Token = generateToken(m1User);
  merchant1Id = m1User.id;

  const m2Hash = await hashPassword(MERCHANT2.password);
  const m2User = await createUser(MERCHANT2.username, m2Hash, MERCHANT2.role);
  merchant2Token = generateToken(m2User);
  merchant2Id = m2User.id;
});

beforeEach(async () => {
  // Phase 1: resetBalancesAndReserve clears protocol tables + all balances
  // to 0 + bank_reserve singleton. Then fundUser properly deposits 100 BC
  // into the customer (updates reserve + assertInvariant). Merchants stay
  // at 0 (only /payment credits merchant.balance).
  const db = getDb();
  await resetBalancesAndReserve(db);
  await fundUser(customerId, 100);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  await closeTestDb();});

// ════════════════════════════════════════════════════════════════
// HAPPY PATH
// ════════════════════════════════════════════════════════════════

describe('M5: payment — happy path', () => {
  it('customer withdraw 10 → merchant deposits → merchant=10, customer=90', async () => {
    const tok = await mintToken(10);
    const res = await api('/api/payment', {
      method: 'POST', token: merchant1Token,
      body: {
        serial: tok.serialHex, amount: tok.amount,
        R_prime: tok.R_primeHex, s_prime: tok.s_primeHex, key_id: tok.keyId, key_id: tok.keyId,
      },
    });
    expect(res.status).toBe(200);
    expect(res.body.deposited).toBe(10);
    expect(res.body.new_balance).toBe(10);

    const db = getDb();
    const m = await db.prepare('SELECT balance FROM users WHERE id = ?').get(merchant1Id);
    expect(m.balance).toBe(10);
    const c = await db.prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(c.balance).toBe(90);  // withdrawn 10 from initial 100
    const sc = await db.prepare('SELECT COUNT(*) AS n FROM spent_coins').get();
    expect(sc.n).toBe(1);
  });
});

// ════════════════════════════════════════════════════════════════
// H3: DOUBLE-SPEND vs RETRY SEMANTICS
// ════════════════════════════════════════════════════════════════

describe('M5: [H3] double-spend vs retry semantics', async () => {
  it('two different merchants concurrent same token → 200 + 409 (true double-spend)', async () => {
    const tok = await mintToken(10);
    const body = {
      serial: tok.serialHex, amount: tok.amount,
      R_prime: tok.R_primeHex, s_prime: tok.s_primeHex, key_id: tok.keyId,
    };
    // Fire both concurrently — BEGIN IMMEDIATE serializes them; the second
    // to acquire the write lock sees the spent row and 409s.
    const [r1, r2] = await Promise.all([
      api('/api/payment', { method: 'POST', token: merchant1Token, body }),
      api('/api/payment', { method: 'POST', token: merchant2Token, body }),
    ]);
    const statuses = [r1.status, r2.status].sort();
    expect(statuses).toEqual([200, 409]);
    // Exactly one merchant got the deposit; the other got nothing.
    const ok = r1.status === 200 ? r1 : r2;
    const bad = r1.status === 200 ? r2 : r1;
    expect(ok.body.deposited).toBe(10);
    expect(bad.body.error).toBe('DOUBLE_SPEND');

    const db = getDb();
    // Total merchant balance incremented by exactly 10 (no double-credit).
    const m1 = await db.prepare('SELECT balance FROM users WHERE id = ?').get(merchant1Id);
    const m2 = await db.prepare('SELECT balance FROM users WHERE id = ?').get(merchant2Id);
    expect(m1.balance + m2.balance).toBe(10);
    const sc = await db.prepare('SELECT COUNT(*) AS n FROM spent_coins').get();
    expect(sc.n).toBe(1);
  });

  it('same merchant re-submits same token → 409 (retry semantics, NOT a bug)', async () => {
    const tok = await mintToken(10);
    const body = {
      serial: tok.serialHex, amount: tok.amount,
      R_prime: tok.R_primeHex, s_prime: tok.s_primeHex, key_id: tok.keyId,
    };
    const r1 = await api('/api/payment', { method: 'POST', token: merchant1Token, body });
    expect(r1.status).toBe(200);
    const r2 = await api('/api/payment', { method: 'POST', token: merchant1Token, body });
    expect(r2.status).toBe(409);
    expect(r2.body.error).toBe('DOUBLE_SPEND');
    // Merchant balance unchanged after the failed retry.
    const db = getDb();
    const m = await db.prepare('SELECT balance FROM users WHERE id = ?').get(merchant1Id);
    expect(m.balance).toBe(10);
  });
});

// ════════════════════════════════════════════════════════════════
// H1: MALFORMED TOKEN FORMAT GATE (DoS defense)
// ════════════════════════════════════════════════════════════════

describe('M5: [H1] malformed token format gate → 400 before verifySig', async () => {
  it('serial 63 hex chars → 400 MALFORMED_TOKEN', async () => {
    const tok = await mintToken(10);
    const res = await api('/api/payment', {
      method: 'POST', token: merchant1Token,
      body: {
        serial: tok.serialHex.slice(0, 63),  // one short
        amount: tok.amount,
        R_prime: tok.R_primeHex,
        s_prime: tok.s_primeHex,
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('MALFORMED_TOKEN');
  });

  it("R_prime prefix 04 (uncompressed) → 400 MALFORMED_TOKEN", async () => {
    const tok = await mintToken(10);
    const res = await api('/api/payment', {
      method: 'POST', token: merchant1Token,
      body: {
        serial: tok.serialHex,
        amount: tok.amount,
        R_prime: '04' + tok.R_primeHex.slice(2),  // swap 02/03 → 04
        s_prime: tok.s_primeHex,
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('MALFORMED_TOKEN');
  });

  it('s_prime 63 hex chars → 400 MALFORMED_TOKEN', async () => {
    const tok = await mintToken(10);
    const res = await api('/api/payment', {
      method: 'POST', token: merchant1Token,
      body: {
        serial: tok.serialHex,
        amount: tok.amount,
        R_prime: tok.R_primeHex,
        s_prime: tok.s_primeHex.slice(0, 63),  // one short
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('MALFORMED_TOKEN');
  });

  it('amount = 0 → 400 MALFORMED_TOKEN', async () => {
    const tok = await mintToken(10);
    const res = await api('/api/payment', {
      method: 'POST', token: merchant1Token,
      body: {
        serial: tok.serialHex,
        amount: 0,
        R_prime: tok.R_primeHex,
        s_prime: tok.s_primeHex,
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('MALFORMED_TOKEN');
  });
});

// ════════════════════════════════════════════════════════════════
// TAMPERED AMOUNT → SIGNATURE INVALID
// ════════════════════════════════════════════════════════════════

describe('M5: tampered amount → verifySig fails 400', async () => {
  it('valid token with amount bumped by 1 → 400 SIGNATURE_INVALID', async () => {
    const tok = await mintToken(10);
    // Sanity: the untampered token verifies locally.
    const validLocal = verifySig(tok.RPrimeBytes, tok.sPrime, tok.serialBytes, 10, tok.publicKey);
    expect(validLocal).toBe(true);

    // Tamper: bump amount to 11 — the signature no longer matches.
    const res = await api('/api/payment', {
      method: 'POST', token: merchant1Token,
      body: {
        serial: tok.serialHex,
        amount: 11,  // tampered!
        R_prime: tok.R_primeHex,
        s_prime: tok.s_primeHex,
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('SIGNATURE_INVALID');

    // Merchant balance untouched (no partial deposit).
    const db = getDb();
    const m = await db.prepare('SELECT balance FROM users WHERE id = ?').get(merchant1Id);
    expect(m.balance).toBe(0);
    const sc = await db.prepare('SELECT COUNT(*) AS n FROM spent_coins').get();
    expect(sc.n).toBe(0);
  });
});

// ════════════════════════════════════════════════════════════════
// ROLE GUARD + AUTH
// ════════════════════════════════════════════════════════════════

describe('M5/M7: role guard unlocked + authentication', async () => {
  it('customer calls /api/payment → 200 (M7: 角色锁已解锁，任何登录用户都能收款)', async () => {
    // 原来 customer 被 merchant 角色锁挡在 403；M7 解锁后 customer 也能存 token。
    // 这样顾客取款后能把 token 转给另一个顾客存款，形成 Chaum 式闭环。
    const tok = await mintToken(10);
    const res = await api('/api/payment', {
      method: 'POST', token: customerToken,
      body: {
        serial: tok.serialHex, amount: tok.amount,
        R_prime: tok.R_primeHex, s_prime: tok.s_primeHex, key_id: tok.keyId, key_id: tok.keyId,
      },
    });
    expect(res.status).toBe(200);
    expect(res.body.deposited).toBe(10);
    // customer 取款 10 (100→90) 又存回 10 (90→100)，余额回到 100
    expect(res.body.new_balance).toBe(100);
  });

  it('unauthenticated call (no token) → 401', async () => {
    const tok = await mintToken(10);
    const res = await api('/api/payment', {
      method: 'POST',  // no token
      body: {
        serial: tok.serialHex, amount: tok.amount,
        R_prime: tok.R_primeHex, s_prime: tok.s_primeHex, key_id: tok.keyId, key_id: tok.keyId,
      },
    });
    expect(res.status).toBe(401);
  });

  it('missing field (no R_prime) → 400 VALIDATION_ERROR', async () => {
    const tok = await mintToken(10);
    const res = await api('/api/payment', {
      method: 'POST', token: merchant1Token,
      body: {
        serial: tok.serialHex, amount: tok.amount,
        // R_prime intentionally omitted
        s_prime: tok.s_primeHex,
      },
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('VALIDATION_ERROR');
  });
});

// ════════════════════════════════════════════════════════════════
// INITIAL BALANCE (Phase 1: 开户改革 — balance=0 on register)
// ════════════════════════════════════════════════════════════════

describe('Phase 1: initial balance — customer registers with balance=0', async () => {
  it('HTTP /api/auth/register customer → balance=0 (Phase 1: 开户改革)', async () => {
    const res = await api('/api/auth/register', {
      method: 'POST',
      body: {
        username: 'carol_' + Date.now(),
        password: 'Passw0rd!extra',
        role: 'customer',
      },
    });
    expect(res.status).toBe(201);
    // Phase 1 (v5 §三 1.5): new users register with balance=0 (was 100).
    // Must POST /api/bank/deposit to fund before withdrawing.
    expect(res.body.user.balance).toBe(0);
    expect(res.body.user.role).toBe('customer');
    // Hint field guides frontend to deposit before withdrawing.
    expect(res.body.hint).toContain('deposit');
  });

  it('HTTP /api/auth/register merchant → balance=0', async () => {
    const res = await api('/api/auth/register', {
      method: 'POST',
      body: {
        username: 'dave_' + Date.now(),
        password: 'Passw0rd!extra',
        role: 'merchant',
      },
    });
    expect(res.status).toBe(201);
    expect(res.body.user.balance).toBe(0);
    expect(res.body.user.role).toBe('merchant');
  });
});
