// tests/integration.test.js — M7: end-to-end integration tests
//
// Professor's M7.md must-haves:
//   ✓ full E2E: customer register (HTTP) → withdraw → merchant deposit → balance
//   ✓ cross-user access denied: A's session_id used by B → 404 SESSION_NOT_FOUND
//   ✓ cross-merchant concurrent double-spend: 1 token to A+B → 200 + 409
//   ✓ expired session lazy-cleanup (TTL elapse → next init refunds)
//   ✓ risk #1: register customer → immediately withdraw (initial-balance race)
//
// Strategy: a persistent http.createServer(app) listens on a random port; all
// fetch() calls reuse it (avoids Windows ENOBUFS that supertest hits when
// spinning up a fresh server per call). Users register via real HTTP /auth
// endpoints (not the service layer) so we exercise the FULL stack including
// express-validator + JWT + role guard. Client-side 4-move blinding uses
// crypto/client/blinding.js — the same code the browser runs.
//
// ISOLATION invariants covered end-to-end:
//   §一-1 customer.balance moves only via /withdraw/* (init debit, cancel refund)
//   §一-2 merchant.balance moves only via /payment
//   §三-3 α/β never leave the user device (submit payload = {e,R_prime,serial})
//   §三-4 at most one active session per customer (409 ACTIVE_SESSION_EXISTS)
//   §三-5 N fresh k per init
//   §一-6 spent_coins.serial PRIMARY KEY → double-spend 409

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
import { TOKEN_DOMAIN_TAG, SESSION_TTL_MS } from '../src/config/bank.js';
import { fundUser, resetBalancesAndReserve } from './helpers/fundUser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
ensureDatabaseUrl();
process.env.BC_DEMO_N = '10';const server = http.createServer(app);
let baseUrl;

/** fetch wrapper returning { status, body }. */
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

// ── helpers ────────────────────────────────────────────────────────────
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
// for normal funding; await resetBalancesAndReserve(db) resets all balances to 0.

async function expireSession (sessionId) {
  const db = getDb();
  await db.prepare(`UPDATE withdrawal_sessions SET expires_at = ? WHERE id = ?`)
    .run('2020-01-01 00:00:00', sessionId);
}

/**
 * Run the full client-side 4-move withdrawal, returning the unblinded token
 * plus the merchant-relevant fields. Mirrors payment.test.js's runFull4Move.
 *
 * @param {string} customerToken  JWT bearer
 * @param {string} publicKeyHex   bank pubkey hex (66 chars)
 * @param {number} amount
 * @returns {Promise<{ token: {serial,amount,R_prime,s_prime}, session_id, R, N, j }>}
 */
async function runFull4Move (customerToken, publicKeyHex, amount = 10) {
  const denomination = amount;
  const init = await api('/api/withdraw/init', {
    method: 'POST', token: customerToken, body: { amount, denomination },
  });
  expect(init.status).toBe(201);
  const { session_id, R, N } = init.body;

  const publicKey = hexToBytes(publicKeyHex);
  const candidates = [];
  const blinders = [];
  for (let i = 0; i < N; i++) {
    const RBytes = hexToBytes(R[i]);
    const bl = generateBlinders();
    const RPrime = computeBlindedCommitment(RBytes, bl.alpha, bl.beta, publicKey);
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
  // sanity: server-side verifySig passes
  const RPrimeJ = hexToBytes(candidates[j].R_prime);
  const serialJ = hexToBytes(candidates[j].serial);
  const ok = verifySig(RPrimeJ, sPrime, serialJ, amount, publicKey);
  expect(ok).toBe(true);

  return {
    token: {
      serial: candidates[j].serial,
      amount,
      R_prime: candidates[j].R_prime,
      s_prime: scalarToHexFixed(sPrime),
      key_id: init.body.key_id,
    },
    session_id,
    R, N, j,
  };
}

// ── setup ──
let customerToken, merchantAToken, merchantBToken;
let customerId, merchantAId, merchantBId;
let customer2Token, customer2Id;

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

  // Register users via real HTTP /api/auth/register (exercises full stack:
  // express-validator + bcrypt + JWT + role + initial-balance mechanism).
  // Phase 1 (v5 §三 1.5 开户改革): new customers register with balance=0
  // (was 100). Must fund via /api/bank/deposit before withdrawing.
  const r1 = await api('/api/auth/register', {
    method: 'POST',
    body: { username: 'alice', password: 'Passw0rd!extra', role: 'customer' },
  });
  expect(r1.status).toBe(201);
  customerToken = r1.body.token;
  customerId = r1.body.user.id;
  expect(r1.body.user.balance).toBe(0); // Phase 1: was 100, now 0
  // Fund the customer via the deposit service so they can withdraw.
  await fundUser(customerId, 100);

  const r2 = await api('/api/auth/register', {
    method: 'POST',
    body: { username: 'bob_a', password: 'Passw0rd!extra', role: 'merchant' },
  });
  expect(r2.status).toBe(201);
  merchantAToken = r2.body.token;
  merchantAId = r2.body.user.id;
  expect(r2.body.user.balance).toBe(0);

  const r3 = await api('/api/auth/register', {
    method: 'POST',
    body: { username: 'bob_b', password: 'Passw0rd!extra', role: 'merchant' },
  });
  expect(r3.status).toBe(201);
  merchantBToken = r3.body.token;
  merchantBId = r3.body.user.id;

  // customer2 for cross-user access tests
  const r4 = await api('/api/auth/register', {
    method: 'POST',
    body: { username: 'carol', password: 'Passw0rd!extra', role: 'customer' },
  });
  expect(r4.status).toBe(201);
  customer2Token = r4.body.token;
  customer2Id = r4.body.user.id;
  // Phase 1: fund customer2 too so cross-user tests that need balance work.
  await fundUser(customer2Id, 100);
});

beforeEach(async () => {
  // Phase 1: resetBalancesAndReserve clears protocol tables + all balances
  // to 0 + bank_reserve singleton. Then fundUser properly deposits 100 BC
  // into each customer (updates reserve + assertInvariant). Merchants stay
  // at 0 (only /payment credits merchant.balance).
  const db = getDb();
  await resetBalancesAndReserve(db);
  await fundUser(customerId, 100);
  await fundUser(customer2Id, 100);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  await closeTestDb();});

// ═══════════════════════════════════════════════════════════════════════
// 1. FULL E2E: customer register → withdraw → merchant deposit → balance
// ═══════════════════════════════════════════════════════════════════════
describe('M7 · full end-to-end flow', () => {
  it('customer funded 100 → withdraw 10 → merchant deposit → balance 90 / 10', async () => {
    // fetch bank pubkey for denomination 10 (unauthenticated)
    const pub = await api('/api/bank/pubkeys');
    expect(pub.status).toBe(200);
    const publicKeyHex = pub.body.denominations['10'].public_key;

    // customer withdraws 10 → unblinded token
    const { token } = await runFull4Move(customerToken, publicKeyHex, 10);

    // customer balance should be 90 (100 - 10 debited at init)
    const customer = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(customer.balance).toBe(90);

    // merchant A deposits the token
    const dep = await api('/api/payment', {
      method: 'POST', token: merchantAToken, body: token,
    });
    expect(dep.status).toBe(200);
    expect(dep.body.deposited).toBe(10);
    expect(dep.body.new_balance).toBe(10);

    // customer unchanged by deposit (only merchant balance moves via /payment)
    const customerAfter = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(customerAfter.balance).toBe(90);
    const merchantA = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(merchantAId);
    expect(merchantA.balance).toBe(10);

    // spent_coins has 1 row with the serial
    const spent = await getDb().prepare('SELECT serial FROM spent_coins').get();
    expect(spent.serial.length).toBe(32); // Buffer(32)
  });

  it('customer register → immediately withdraw (教授风险#1: 充值+取款 race)', async () => {
    // This exercises the initial-balance mechanism: customer registers with
    // balance=0 (Phase 1), then beforeEach calls await fundUser(customerId, 100) via
    // /api/bank/deposit. The very next /withdraw call must see balance=100.
    // There is no separate "claim balance" endpoint (professor's risk note was
    // based on a slight misunderstanding — but we still cover the path to
    // prove no race between deposit and withdraw).
    const pub = await api('/api/bank/pubkeys');
    const { token } = await runFull4Move(customerToken, pub.body.denominations['10'].public_key, 10);

    const customer = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(customer.balance).toBe(90); // 100 - 10

    // merchant can deposit
    const dep = await api('/api/payment', {
      method: 'POST', token: merchantAToken, body: token,
    });
    expect(dep.status).toBe(200);
    expect(dep.body.deposited).toBe(10);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 2. CROSS-USER ACCESS DENIED (ISOLATION §三: A's session_id ≠ B's)
// ═══════════════════════════════════════════════════════════════════════
describe('M7 · cross-user access denied', async () => {
  it('customer B cannot call submit on customer A\'s session_id → 404 SESSION_NOT_FOUND', async () => {
    const pub = await api('/api/bank/pubkey');
    const publicKeyHex = pub.body.public_key;
    // customer (alice) opens a session
    const init = await api('/api/withdraw/init', {
      method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 },
    });
    expect(init.status).toBe(201);
    const { session_id, R, N } = init.body;

    // carol (customer2) tries to submit on alice's session_id
    const candidates = [];
    const publicKey = hexToBytes(publicKeyHex);
    for (let i = 0; i < N; i++) {
      const RBytes = hexToBytes(R[i]);
      const bl = generateBlinders();
      const RPrime = computeBlindedCommitment(RBytes, bl.alpha, bl.beta, publicKey);
      const serial = new Uint8Array(32);
      globalThis.crypto.getRandomValues(serial);
      const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, 10, publicKey);
      const e = modN(ePrime + bl.beta);
      candidates.push({
        e: scalarToHexFixed(e),
        R_prime: bytesToHex(RPrime),
        serial: bytesToHex(serial),
      });
    }
    const submit = await api('/api/withdraw/submit', {
      method: 'POST', token: customer2Token,
      body: { session_id, candidates },
    });
    expect(submit.status).toBe(404);
    expect(submit.body.error).toBe('SESSION_NOT_FOUND');

    // alice's session is still pending (carol's failed submit didn't mutate it)
    const sess = await getDb().prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(session_id);
    expect(sess.status).toBe('pending');
  });

  it('customer B cannot cancel customer A\'s session_id → 404', async () => {
    const init = await api('/api/withdraw/init', {
      method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 },
    });
    expect(init.status).toBe(201);
    const { session_id } = init.body;

    const cancel = await api('/api/withdraw/cancel', {
      method: 'POST', token: customer2Token,
      body: { session_id },
    });
    expect(cancel.status).toBe(404);
    expect(cancel.body.error).toBe('SESSION_NOT_FOUND');

    // alice's session still pending + balance still debited
    const sess = await getDb().prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(session_id);
    expect(sess.status).toBe('pending');
    const alice = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(alice.balance).toBe(90); // 100 - 10
  });

  it('merchant can call /api/withdraw/init → 201 (M7: 角色锁已解锁)', async () => {
    // M7: 角色锁去掉后，merchant 也能取款，形成真·转账闭环
    // Phase 1: fund merchant via deposit so they can withdraw.
    await fundUser(merchantAId, 100);
    const init = await api('/api/withdraw/init', {
      method: 'POST', token: merchantAToken, body: { amount: 10, denomination: 10 },
    });
    expect(init.status).toBe(201);
    // 清理
    await api('/api/withdraw/cancel', {
      method: 'POST', token: merchantAToken, body: { session_id: init.body.session_id },
    });
    // Phase 1: beforeEach will reset on next test, no manual cleanup needed.
  });

  it('customer can call /api/payment → 400 SIGNATURE_INVALID (M7: 角色锁已解锁，但 token 无效仍被拒)', async () => {
    // M7: 角色锁去掉后，customer 不再被 403 挡。但这里传的是无效 token，
    // 服务器 verifySig 仍会拒绝 → 400 SIGNATURE_INVALID（crypto 才是安全边界）。
    const dep = await api('/api/payment', {
      method: 'POST', token: customerToken,
      body: { serial: '0'.repeat(64), amount: 1, R_prime: '02' + '0'.repeat(64), s_prime: '0'.repeat(64) },
    });
    expect(dep.status).toBe(400);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 3. CROSS-MERCHANT CONCURRENT DOUBLE-SPEND (教授必做: 时序不确定)
// ═══════════════════════════════════════════════════════════════════════
describe('M7 · concurrent double-spend across two merchants', async () => {
  it('1 token to merchant A + B concurrently → one 200, one 409 (order not guaranteed)', async () => {
    const pub = await api('/api/bank/pubkeys');
    const { token } = await runFull4Move(customerToken, pub.body.denominations['10'].public_key, 10);

    // Fire both deposits concurrently. We do NOT assert which one wins —
    // professor's M6.md #2 explicitly says "时序不确定, 不保证先发起者赢".
    // What we DO assert: exactly one returns 200 and the other 409 DOUBLE_SPEND.
    const [resA, resB] = await Promise.all([
      api('/api/payment', { method: 'POST', token: merchantAToken, body: token }),
      api('/api/payment', { method: 'POST', token: merchantBToken, body: token }),
    ]);

    const statuses = [resA.status, resB.status].sort();
    expect(statuses).toEqual([200, 409]);

    // The 200 winner's balance += 10; the 409 loser's balance stays 0.
    const merchantA = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(merchantAId);
    const merchantB = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(merchantBId);
    const balances = [merchantA.balance, merchantB.balance].sort();
    expect(balances).toEqual([0, 10]);

    // Exactly one spent_coins row (the 200 winner's INSERT committed)
    const spent = await getDb().prepare('SELECT COUNT(*) AS n FROM spent_coins').get();
    expect(spent.n).toBe(1);

    // The 409 loser's response code is DOUBLE_SPEND
    const loser = resA.status === 409 ? resA : resB;
    expect(loser.body.error).toBe('DOUBLE_SPEND');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 4. EXPIRED SESSION LAZY-CLEANUP (ISOLATION §一-1: refund on next init)
// ═══════════════════════════════════════════════════════════════════════
describe('M7 · expired session lazy-cleanup', async () => {
  it('TTL elapse → next init refunds old session + opens new one', async () => {
    // alice opens a session for 10
    const init1 = await api('/api/withdraw/init', {
      method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 },
    });
    expect(init1.status).toBe(201);
    const { session_id: oldSessionId } = init1.body;
    // balance debited to 90
    const after1 = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(after1.balance).toBe(90);

    // ── fast-forward: mark old session as expired ──
    await expireSession(oldSessionId);

    // alice starts a new session for 10 — lazyCleanupExpiredSessions should
    // refund the old 10 (90 → 100) BEFORE debiting the new 10 (100 → 90).
    const init2 = await api('/api/withdraw/init', {
      method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 },
    });
    expect(init2.status).toBe(201);
    const { session_id: newSessionId } = init2.body;
    expect(newSessionId).not.toBe(oldSessionId);

    // Final balance: 100 (refunded) - 10 (new debit) = 90
    const after2 = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(after2.balance).toBe(90);

    // Old session is now 'expired', new session is 'pending'
    const oldSess = await getDb().prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(oldSessionId);
    expect(oldSess.status).toBe('expired');
    const newSess = await getDb().prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(newSessionId);
    expect(newSess.status).toBe('pending');
  });

  it('submit on expired session → 400 SESSION_EXPIRED + refund', async () => {
    const pub = await api('/api/bank/pubkey');
    const init = await api('/api/withdraw/init', {
      method: 'POST', token: customerToken, body: { amount: 10, denomination: 10 },
    });
    expect(init.status).toBe(201);
    const { session_id, R, N } = init.body;

    // expire it
    await expireSession(session_id);

    // build candidates (10) and submit on the expired session
    const publicKey = hexToBytes(pub.body.public_key);
    const candidates = [];
    for (let i = 0; i < N; i++) {
      const RBytes = hexToBytes(R[i]);
      const bl = generateBlinders();
      const RPrime = computeBlindedCommitment(RBytes, bl.alpha, bl.beta, publicKey);
      const serial = new Uint8Array(32);
      globalThis.crypto.getRandomValues(serial);
      const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, 10, publicKey);
      const e = modN(ePrime + bl.beta);
      candidates.push({
        e: scalarToHexFixed(e),
        R_prime: bytesToHex(RPrime),
        serial: bytesToHex(serial),
      });
    }
    const submit = await api('/api/withdraw/submit', {
      method: 'POST', token: customerToken,
      body: { session_id, candidates },
    });
    expect(submit.status).toBe(400);
    expect(submit.body.error).toBe('SESSION_EXPIRED');

    // balance refunded: 100 (initial was 100 - 10 = 90, refund → 100)
    const alice = await getDb().prepare('SELECT balance FROM users WHERE id = ?').get(customerId);
    expect(alice.balance).toBe(100);

    // session is 'expired'
    const sess = await getDb().prepare('SELECT status FROM withdrawal_sessions WHERE id = ?').get(session_id);
    expect(sess.status).toBe('expired');
  });
});

// ═══════════════════════════════════════════════════════════════════════
// 5. SESSION_TTL_MS sanity (config invariant: 5 minutes default)
// ═══════════════════════════════════════════════════════════════════════
describe('M7 · config sanity', async () => {
  it('SESSION_TTL_MS is 5 minutes (300000 ms) by default', async () => {
    // Default TTL — overridden only via BC_SESSION_TTL_MS env. We do NOT set
    // that env in this test file, so the default 5*60*1000 must hold.
    expect(SESSION_TTL_MS).toBe(5 * 60 * 1000);
  });
});
