// tests/bankKeyService.test.js — M3: bank keypair persistence + /api/bank/pubkey
//
// v3 §5 M3 test list (≥5 cases, see §6 验证矩阵 M3 row):
//   ✓ first boot: getOrGenerate() creates a keypair, bank_keys has exactly 1 row (id=1)
//   ✓ second boot: after closeDb + cache reset, getOrGenerate() reads the SAME keypair
//     (does NOT regenerate — would invalidate previously-issued tokens)
//   ✓ keypair format: publicKey 33B + prefix 0x02/0x03 + isOnCurve;
//     privateKey 32B + scalar ∈ [1, n-1]; P == x·G (re-derive from private key)
//   ✓ GET /api/bank/pubkey returns correct hex (66 chars, prefix 02/03, matches service)
//   ✓ GET /api/bank/pubkey response body has NO private_key field (defensive)
//
// ⚠ ISOLATION.md §五 不变量 7: tests do NOT use read-private-key as a "proof"
//   of any security property. The P == x·G re-derivation below is a
//   SELF-CONSISTENCY check of stored data (catches DB corruption), NOT a
//   protocol security argument.

import { describe, it, expect, beforeEach, afterEach, afterAll } from 'vitest';
import { rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';

import {
  getOrGenerate,
  getPublicKey,
  getPrivateKey,
  _resetCacheForTest,
} from '../src/services/bankKeyService.js';
import { initSchema, getDb, closeDb, queryOne } from '../src/models/db.js';
import {
  G,
  n,
  isOnCurve,
  bytesToScalar,
  isValidScalar,
} from '../src/crypto/server/curve.js';
import { bytesToHex } from '../src/utils/hex.js';
import app from '../src/app.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_PATH = join(__dirname, '..', 'data', 'test-m3-bankkeys.db');
process.env.BC_DB_PATH = TEST_DB_PATH;

// Module-level schema init (cryptobank pattern). initSchema() is idempotent
// (CREATE TABLE IF NOT EXISTS) and calls closeDb() first so the singleton
// _db is reset against the TEST_DB_PATH we just set.
initSchema();

beforeEach(() => {
  // Start each test with a clean bank_keys table + cleared cache.
  // (users table is untouched — these tests don't touch user data.)
  const db = getDb();
  db.exec('DELETE FROM bank_keys;');
  _resetCacheForTest();
});

afterEach(() => {
  _resetCacheForTest();
});

afterAll(() => {
  closeDb();
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(TEST_DB_PATH + suffix, { force: true }); } catch {}
  }
});

describe('M3 · bankKeyService — keypair persistence (singleton row id=1)', () => {
  describe('getOrGenerate(): first boot generates + persists', () => {
    it('creates exactly one row in bank_keys with id=1 on first call', () => {
      const kp = getOrGenerate();

      // The returned keypair should be the same one stored in the DB.
      const row = queryOne(
        'SELECT id, public_key, private_key FROM bank_keys',
      );
      expect(row).toBeDefined();
      expect(row.id).toBe(1);
      expect(new Uint8Array(row.public_key)).toStrictEqual(kp.publicKey);
      expect(new Uint8Array(row.private_key)).toStrictEqual(kp.privateKey);
    });

    it('does NOT insert a second row on a second call (cache hit)', () => {
      getOrGenerate();       // first call: inserts
      getOrGenerate();       // second call: cache hit, no DB write

      const rows = queryOne('SELECT COUNT(*) AS cnt FROM bank_keys');
      expect(rows.cnt).toBe(1);
    });
  });

  describe('getOrGenerate(): second boot reads back the SAME keypair', () => {
    // This is the critical "no regeneration on reboot" test. We:
    //   1. generate a keypair (inserts row)
    //   2. closeDb() + _resetCacheForTest() — simulate process exit
    //   3. call getOrGenerate() again — should READ the existing row,
    //      not generate a new one.
    it('reads the existing keypair after closeDb + cache reset (no regeneration)', () => {
      const first = getOrGenerate();
      const firstPubHex = bytesToHex(first.publicKey);
      const firstPrivHex = bytesToHex(first.privateKey);

      // Simulate process restart: close DB handle + clear in-memory cache.
      // The row persists on disk in TEST_DB_PATH.
      closeDb();
      _resetCacheForTest();

      // Re-initialize schema (reopens DB, CREATE TABLE IF NOT EXISTS is a
      // no-op on the existing table).
      initSchema();

      const second = getOrGenerate();
      expect(bytesToHex(second.publicKey)).toBe(firstPubHex);
      expect(bytesToHex(second.privateKey)).toBe(firstPrivHex);
    });
  });

  describe('keypair format + self-consistency (P == x·G)', () => {
    // NOTE: this is a SELF-CONSISTENCY check of stored data, not a security
    // proof (ISOLATION §五 不变量 7). It catches DB corruption where the
    // pubkey was swapped but the private key wasn't (or vice versa).
    it('publicKey: 33 bytes, prefix 0x02/0x03, on-curve', () => {
      const kp = getOrGenerate();
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey.length).toBe(33);
      expect([0x02, 0x03]).toContain(kp.publicKey[0]);
      expect(isOnCurve(kp.publicKey)).toBe(true);
    });

    it('privateKey: 32 bytes, scalar ∈ [1, n-1]', () => {
      const kp = getOrGenerate();
      expect(kp.privateKey).toBeInstanceOf(Uint8Array);
      expect(kp.privateKey.length).toBe(32);
      const x = bytesToScalar(kp.privateKey);
      expect(isValidScalar(x)).toBe(true);   // 1 ≤ x < n
    });

    it('P == x·G (re-derive public key from private key)', () => {
      const kp = getOrGenerate();
      const x = bytesToScalar(kp.privateKey);
      const P = G.multiply(x);
      const PBytes = P.toRawBytes(true); // 33-byte compressed
      expect(PBytes).toStrictEqual(kp.publicKey);
    });
  });

  describe('getPublicKey() / getPrivateKey() accessors', () => {
    it('getPublicKey() returns the same 33B as getOrGenerate().publicKey', () => {
      const kp = getOrGenerate();
      expect(getPublicKey()).toStrictEqual(kp.publicKey);
    });

    it('getPrivateKey() returns the same 32B as getOrGenerate().privateKey', () => {
      const kp = getOrGenerate();
      expect(getPrivateKey()).toStrictEqual(kp.privateKey);
    });
  });
});

describe('M3 · GET /api/bank/pubkey — public key endpoint (no auth)', () => {
  // Pre-populate the cache + DB row so the route handler returns from cache.
  // (The route calls getPublicKey() which lazily calls getOrGenerate() if
  // cache is empty — but we want a deterministic key for the assertions.)
  let cachedPubHex;
  beforeEach(() => {
    const kp = getOrGenerate();
    cachedPubHex = bytesToHex(kp.publicKey);
  });

  it('returns 200 + { public_key: hex } matching the service key', async () => {
    const res = await request(app).get('/api/bank/pubkey');
    expect(res.status).toBe(200);
    expect(res.body.public_key).toBe(cachedPubHex);
    expect(res.body.encoding).toBe('secp256k1-compressed');
    expect(res.body.byte_length).toBe(33);
  });

  it('returns a 66-char hex string starting with 02 or 03', async () => {
    const res = await request(app).get('/api/bank/pubkey');
    expect(res.body.public_key).toMatch(/^(02|03)[0-9a-f]{64}$/);
    expect(res.body.public_key).toHaveLength(66);
  });

  it('response body has NO private_key field (defensive)', async () => {
    const res = await request(app).get('/api/bank/pubkey');
    // Stringify the body and assert the word "private" never appears —
    // catches accidental leakage under any field name.
    const bodyStr = JSON.stringify(res.body).toLowerCase();
    expect(bodyStr).not.toContain('private');
  });

  it('does NOT require authentication (no Authorization header)', async () => {
    // A bare request with no auth header must succeed (200), not 401.
    const res = await request(app).get('/api/bank/pubkey');
    expect(res.status).not.toBe(401);
    expect(res.status).toBe(200);
  });
});
