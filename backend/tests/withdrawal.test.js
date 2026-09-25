// tests/withdrawal.test.js — M4: 4-move withdrawal protocol (≥18 cases)
//
// v3 §5 M4 test list + professor's 3 must-tests:
//   ✓ happy path: 4-move full flow, balance 100 withdraw 30 → 70, verifySig passes
//   ✓ token verifySig: (R', s') verifies locally after unblind
//   ✓ insufficient balance → 400
//   ✓ amount ≤ 0 → 400
//   ✓ merchant calls init → 403
//   ✓ candidate count ≠ N → 400
//   ✓ reveal i-set ≠ {0..N-1}\{j} (incomplete) → 400
//   ✓ duplicate reveal (same session) → 409
//   ✓ cut-and-choose tamper (wrong alpha) → 400 + refund
//   ✓ [必测#2] concurrent second pending session → 409 (不变量 4)
//   ✓ [必测#1] submit payload carries α/β → 400 (不变量 3)
//   ✓ [必测#3] reveal payload carries j-candidate → 400 (不变量 3)
//   ✓ [必测#3] abandoned session, TTL elapse, next init triggers refund
//   ✓ [必测#3] submit on expired session → 400 + refund
//   ✓ cancel pending → refund + cancelled
//   ✓ cancel submitted → refund + cancelled
//   ✓ cancel another user's session → 403 (role guard)
//   ✓ cancel committed → 400 (irreversible)
//
// Test strategy: a persistent http.createServer(app) listens on a random
// port; fetch() reuses it to avoid the Windows ENOBUFS problem that supertest
// hits when spinning up a fresh server per call.
// Users register once in beforeAll; beforeEach only clears protocol tables
// and resets balance. Client-side blinding math uses crypto/client/blinding.js
// (the same code the browser would run).

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
process.env.BC_DEMO_N = '10';// Persistent server: one listen socket, fetch() reuses it. Avoids the Windows
// ENOBUFS problem that supertest hits when spinning up a fresh server per call.
const server = http.createServer(app);
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

const CUSTOMER = { username: 'alice', password: 'Passw0rd!extra', role: 'customer' };
const MERCHANT = { username: 'bob', password: 'Passw0rd!extra', role: 'merchant' };

let customerToken, merchantToken, customerId, merchantId;

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

// Phase 1: setBalance removed — direct UPDATE users.balance without
// updating bank_reserve breaks assertInvariant. Use await fundUser(id, amount)
// (which calls bankService.deposit) for normal "give this user balance"
// needs. The only place we still want balance=0 is the merchant in
// beforeEach — and await resetBalancesAndReserve(db) already sets ALL users to 0.

async function expireSession (sessionId) {
  const db = getDb();
  await db.prepare(`UPDATE withdrawal_sessions SET expires_at = ? WHERE id = ?`)
    .run('2020-01-01 00:00:00', sessionId);
}

/**
 * Run the full client-side blinding for all N candidates given bank R_i list.
 * Returns { candidates, blinders } where:
 *   candidates[i] = { e, R_prime, serial }  (for submit)
 *   blinders[i]   = { alpha, beta }  (kept locally)
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

/** Full 4-move happy path, returning the final token + intermediates. */
async function runFull4Move (amount = 10) {
  const denomination = amount;
  const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount, denomination } });
  expect(init.status).toBe(201);
  const { session_id, R, N } = init.body;

  const pubRes = await api('/api/bank/pubkeys');
  const publicKeyHex = pubRes.body.denominations[String(denomination)].public_key;
  const { candidates, blinders } = await clientBuildCandidates(R, amount, publicKeyHex);

  const submit = await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id, candidates } });
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
  const reveal = await api('/api/withdraw/reveal', { method: 'POST', token: customerToken, body: { session_id, revealed } });
  expect(reveal.status).toBe(200);
  const sJ = hexToScalarFixed(reveal.body.s_j);

  const sPrime = unblindResponse(sJ, blinders[j].alpha);
  const RPrimeJ = hexToBytes(candidates[j].R_prime);
  const serialJ = hexToBytes(candidates[j].serial);
  const publicKey = hexToBytes(publicKeyHex);
  const valid = verifySig(RPrimeJ, sPrime, serialJ, amount, publicKey);

  return { init, submit, reveal, valid, session_id, j, sPrime, RPrimeJ, serialJ, amount, publicKey, N };
}

// ── setup: start server + create users via service layer (no HTTP overhead) ──

beforeAll(async () => {
  // start the persistent server on a random port
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;

  // clear all tables (in case DB file has leftover data from prior failed runs)
  const db = getDb();
  await resetTestDb();
  await db.exec('DELETE FROM withdrawal_sessions;');
  await db.exec('DELETE FROM spent_coins;');
  await db.exec('DELETE FROM transactions;');
  await db.exec('DELETE FROM users;');
  await db.exec('DELETE FROM bank_keys;');
  // Phase 1: also reset bank_reserve singleton to 0 (otherwise leftover
  // total_issued/total_redeemed from prior runs would break assertInvariant).
  await db.exec('UPDATE bank_reserve SET total_issued=0, total_redeemed=0, reserve_balance=0 WHERE id=1;');

  // create users directly via service layer (avoids HTTP registration overhead)
  // Phase 1: new users register with balance=0; we fund the customer below.
  const cHash = await hashPassword(CUSTOMER.password);
  const cUser = await createUser(CUSTOMER.username, cHash, CUSTOMER.role);
  customerToken = generateToken(cUser);
  customerId = cUser.id;

  const mHash = await hashPassword(MERCHANT.password);
  const mUser = await createUser(MERCHANT.username, mHash, MERCHANT.role);
  merchantToken = generateToken(mUser);
  merchantId = mUser.id;

  // Phase 1: fund the customer with 100 BC via deposit (properly updates
  // bank_reserve + assertInvariant). Merchant stays at 0 (only /payment credits).
  await fundUser(customerId, 100);
});

beforeEach(async () => {
  // Phase 1: resetBalancesAndReserve clears protocol tables + all user
  // balances to 0 + bank_reserve singleton to 0. Then fundUser properly
  // deposits 100 BC into the customer (updates reserve + assertInvariant).
  // Merchant stays at 0 (only /payment credits merchant.balance).
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

describe('M4: 4-move withdrawal — happy path', () => {
  it('full 4-move flow: balance 100 → withdraw 10 → 90, verifySig passes', async () => {
    const result = await runFull4Move(10);
    expect(result.valid).toBe(true);
    const db = getDb();
    const user = await db.prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(user.balance).toBe(90);
    const sess = await db.prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(result.session_id);
    expect(sess.status).toBe('committed');
  });

  it('token verifySig: (R\', s\') verifies locally after unblind', async () => {
    const result = await runFull4Move(10);
    expect(result.valid).toBe(true);
    const tampered = result.sPrime + 1n;
    const bad = verifySig(result.RPrimeJ, tampered, result.serialJ, result.amount, result.publicKey);
    expect(bad).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════
// VALIDATION / EDGE CASES
// ════════════════════════════════════════════════════════════════

describe('M4: validation errors', async () => {
  it('insufficient balance → 400', async () => {
    // balance 100 < amount 100 is false, so reset balance to 0 to test
    // INSUFFICIENT_BALANCE (100 仍在白名单内但 > balance).
    const db = getDb();
    await resetBalancesAndReserve(db);
    const res = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 100, denomination: 100 } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('INSUFFICIENT_BALANCE');
  });

  it('amount ≤ 0 → 400', async () => {
    const res = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 0, denomination: 1 } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('INVALID_AMOUNT');
  });

  it('merchant calls init → 201 (M7: 角色锁已解锁，任何登录用户都能取款)', async () => {
    // Phase 1: fund merchant via deposit so they can withdraw.
    await fundUser(merchantId, 100);
    const res = await api('/api/withdraw/init', { method: 'POST', token: merchantToken, body: { amount: 10, denomination: 10 } });
    expect(res.status).toBe(201);
    expect(res.body.amount).toBe(10);
    // 清理：取消该 session 退回余额
    await api('/api/withdraw/cancel', { method: 'POST', token: merchantToken, body: { session_id: res.body.session_id } });
    // Phase 1: merchant balance now 100 again (refund). beforeEach will reset
    // on the next test, so no manual setBalance(merchantId, 0) needed here.
  });

  it('candidate count ≠ N → 400', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const pub = await api('/api/bank/pubkey');
    // submit only N-1 candidates
    const { candidates } = await clientBuildCandidates(init.body.R.slice(0, -1), 10, pub.body.public_key);
    const res = await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, candidates } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('CANDIDATE_COUNT');
  });

  it('reveal i-set incomplete (N-2 instead of N-1) → 400', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const pub = await api('/api/bank/pubkey');
    const { candidates, blinders } = await clientBuildCandidates(init.body.R, 10, pub.body.public_key);
    const submit = await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, candidates } });
    const j = submit.body.j;

    // reveal only N-2 (skip one i≠j)
    const revealed = [];
    let skipped = false;
    for (let i = 0; i < init.body.N; i++) {
      if (i === j) continue;
      if (!skipped) { skipped = true; continue; }
      revealed.push({
        i,
        alpha: scalarToHexFixed(blinders[i].alpha),
        beta: scalarToHexFixed(blinders[i].beta),
      });
    }
    const res = await api('/api/withdraw/reveal', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, revealed } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('REVEAL_COUNT');
  });

  it('duplicate reveal (committed session re-revealed) → 409', async () => {
    const result = await runFull4Move(10);
    const revealed = [];
    for (let i = 0; i < result.N; i++) {
      if (i === result.j) continue;
      revealed.push({ i, alpha: '0'.repeat(64), beta: '0'.repeat(64) });
    }
    const res = await api('/api/withdraw/reveal', { method: 'POST', token: customerToken, body: { session_id: result.session_id, revealed } });
    expect(res.status).toBe(409);
  });

  it('cut-and-choose tamper (wrong alpha) → 400 + refund', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const pub = await api('/api/bank/pubkey');
    const { candidates, blinders } = await clientBuildCandidates(init.body.R, 10, pub.body.public_key);
    const submit = await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, candidates } });
    const j = submit.body.j;

    // tamper: wrong alpha for first i≠j
    const revealed = [];
    let tampered = false;
    for (let i = 0; i < init.body.N; i++) {
      if (i === j) continue;
      let alpha = blinders[i].alpha;
      if (!tampered) { alpha = alpha + 1n; tampered = true; }
      revealed.push({
        i,
        alpha: scalarToHexFixed(alpha),
        beta: scalarToHexFixed(blinders[i].beta),
      });
    }
    const res = await api('/api/withdraw/reveal', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, revealed } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('CUT_AND_CHOOSE_FAILED');
    const db = getDb();
    const user = await db.prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(user.balance).toBe(100);
    const sess = await db.prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(init.body.session_id);
    expect(sess.status).toBe('aborted');
  });
});

// ════════════════════════════════════════════════════════════════
// PROFESSOR MUST-TEST #1: submit carries α/β → 400 (不变量 3)
// ════════════════════════════════════════════════════════════════

describe('M4: [必测#1] blindness invariant 3 — α/β must not leave user device', async () => {
  it('submit payload carries alpha field → 400', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const pub = await api('/api/bank/pubkey');
    const { candidates } = await clientBuildCandidates(init.body.R, 10, pub.body.public_key);
    candidates[0].alpha = '0'.repeat(64);
    const res = await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, candidates } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('BLINDER_LEAKED');
  });

  it('submit payload carries beta field → 400', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const pub = await api('/api/bank/pubkey');
    const { candidates } = await clientBuildCandidates(init.body.R, 10, pub.body.public_key);
    candidates[3].beta = '0'.repeat(64);
    const res = await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, candidates } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('BLINDER_LEAKED');
  });

  it('reveal payload carries j-candidate → 400', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const pub = await api('/api/bank/pubkey');
    const { candidates, blinders } = await clientBuildCandidates(init.body.R, 10, pub.body.public_key);
    const submit = await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, candidates } });
    const j = submit.body.j;

    // reveal INCLUDING j (the forbidden one)
    const revealed = [];
    for (let i = 0; i < init.body.N; i++) {
      revealed.push({
        i,
        alpha: scalarToHexFixed(blinders[i].alpha),
        beta: scalarToHexFixed(blinders[i].beta),
      });
    }
    const res = await api('/api/withdraw/reveal', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, revealed } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('SIGNED_CANDIDATE_REVEALED');
  });
});

// ════════════════════════════════════════════════════════════════
// PROFESSOR MUST-TEST #2: concurrent active session → 409 (不变量 4)
// ════════════════════════════════════════════════════════════════

describe('M4: [必测#2] session uniqueness invariant 4', async () => {
  it('second init while one pending → 409', async () => {
    const first = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    expect(first.status).toBe(201);
    const second = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    expect(second.status).toBe(409);
    expect(second.body.error).toBe('ACTIVE_SESSION_EXISTS');
  });
});

// ════════════════════════════════════════════════════════════════
// PROFESSOR MUST-TEST #3: expired session lazy-cleanup refund (TTL)
// ════════════════════════════════════════════════════════════════

describe('M4: [必测#3] expired session lazy-cleanup refund', async () => {
  it('abandoned session, TTL elapse, next init triggers refund', async () => {
    const first = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    expect(first.status).toBe(201);
    const db = getDb();
    let user = await db.prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(user.balance).toBe(90);

    await expireSession(first.body.session_id);

    const second = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    expect(second.status).toBe(201);
    // refund 90→100, new debit 100→90
    user = await db.prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(user.balance).toBe(90);
    const oldSess = await db.prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(first.body.session_id);
    expect(oldSess.status).toBe('expired');
  });

  it('submit on expired session → 400 + refund', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    await expireSession(init.body.session_id);
    const pub = await api('/api/bank/pubkey');
    const { candidates } = await clientBuildCandidates(init.body.R, 10, pub.body.public_key);
    const res = await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, candidates } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('SESSION_EXPIRED');
    const db = getDb();
    const user = await db.prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(user.balance).toBe(100);
  });
});

// ════════════════════════════════════════════════════════════════
// CANCEL FLOW
// ════════════════════════════════════════════════════════════════

describe('M4: cancel flow', async () => {
  it('cancel pending session → refund + cancelled', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const res = await api('/api/withdraw/cancel', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id } });
    expect(res.status).toBe(200);
    expect(res.body.refunded).toBe(10);
    expect(res.body.new_balance).toBe(100);
    const db = getDb();
    const sess = await db.prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(init.body.session_id);
    expect(sess.status).toBe('cancelled');
  });

  it('cancel submitted session → refund + cancelled', async () => {
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const pub = await api('/api/bank/pubkey');
    const { candidates } = await clientBuildCandidates(init.body.R, 10, pub.body.public_key);
    await api('/api/withdraw/submit', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id, candidates } });
    const res = await api('/api/withdraw/cancel', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id } });
    expect(res.status).toBe(200);
    expect(res.body.refunded).toBe(10);
    const db = getDb();
    const sess = await db.prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(init.body.session_id);
    expect(sess.status).toBe('cancelled');
  });

  it('merchant cancel customer session → 404 (M7: 角色锁已解锁，但 session 归属仍隔离)', async () => {
    // 角色锁虽解锁，但 cancelWithdrawal 查询带 customer_id = req.user.userId，
    // merchant 不是 session 的 owner → 查不到 → 404 SESSION_NOT_FOUND
    const init = await api('/api/withdraw/init', { method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 } });
    const res = await api('/api/withdraw/cancel', { method: 'POST', token: merchantToken, body: { session_id: init.body.session_id } });
    expect(res.status).toBe(404);
    expect(res.body.error).toBe('SESSION_NOT_FOUND');
    // 清理 customer 的 active session
    await api('/api/withdraw/cancel', { method: 'POST', token: customerToken, body: { session_id: init.body.session_id } });
  });

  it('cancel committed session → 400 (irreversible)', async () => {
    const result = await runFull4Move(10);
    const res = await api('/api/withdraw/cancel', { method: 'POST', token: customerToken, body: { session_id: result.session_id } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('NOT_CANCELLABLE');
  });
});
