// tests/bankKeyService.test.js — M3: bank keypair persistence + /api/bank/pubkey
//
// v3 §5 M3 test list (≥5 cases, see §6 验证矩阵 M3 row):
//   ✓ first boot: await getOrGenerate() creates a keypair, bank_keys has exactly 1 row (id=1)
//   ✓ second boot: after closeDb + cache reset, await getOrGenerate() reads the SAME keypair
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
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';

import {
  getOrGenerate,
  getPublicKey,
  getPrivateKey,
  getActivePublicKey,
  getActiveKeyVersion,
  getPublicKeyByVersion,
  rotateKey,
  BankKeyError,
  _resetCacheForTest,
} from '../src/services/bankKeyService.js';
import { getDb, closeDb, queryOne, runWrite } from '../src/models/db.js';
import { resetTestDb, ensureDatabaseUrl, closeTestDb } from './helpers/testDb.js';
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
ensureDatabaseUrl();
// Module-level schema init (cryptobank pattern). initSchema() is idempotent
// (CREATE TABLE IF NOT EXISTS) and calls await closeDb() first so the singleton
// _db is reset against the TEST_DB_PATH we just set.beforeEach(async () => {
  // Start each test with a clean bank_keys table + cleared cache.
  // (users table is untouched — these tests don't touch user data.)
  const db = getDb();
  await resetTestDb();
  await db.exec('DELETE FROM bank_keys;');
  _resetCacheForTest();
});

afterEach(async () => {
  _resetCacheForTest();
});

afterAll(async () => {
  await closeTestDb();
  for (const suffix of ['', '-wal', '-shm']) {

  }
});

describe('M3 · bankKeyService — keypair persistence (multi-key Phase 3)', () => {
  describe('await getOrGenerate(): first boot generates + persists', () => {
    it('creates exactly one row in bank_keys with key_version=1 on first call', async () => {
      const kp = await getOrGenerate();

      // The returned keypair should be the same one stored in the DB.
      // Phase 3: private_key is now AES-256-GCM encrypted (60 bytes), not
      // plaintext (32 bytes). We check public_key matches and private_key
      // is NOT the plaintext (length ≠ 32).
      const row = await queryOne(
        'SELECT key_version, public_key, private_key, status FROM bank_keys',
      );
      expect(row).toBeDefined();
      expect(row.key_version).toBe(1);
      expect(row.status).toBe('active');
      expect(new Uint8Array(row.public_key)).toStrictEqual(kp.publicKey);
      // private_key in DB should be encrypted (60 bytes), NOT the raw 32-byte
      // plaintext that getOrGenerate returns in memory.
      expect(row.private_key.length).toBe(60);
      expect(new Uint8Array(row.private_key)).not.toStrictEqual(kp.privateKey);
    });

    it('does NOT insert a second row on a second call (cache hit)', async () => {
      await getOrGenerate();       // first call: inserts
      await getOrGenerate();       // second call: cache hit, no DB write

      const rows = await queryOne('SELECT COUNT(*) AS cnt FROM bank_keys');
      expect(rows.cnt).toBe(1);
    });
  });

  describe('await getOrGenerate(): second boot reads back the SAME keypair', () => {
    // This is the critical "no regeneration on reboot" test. We:
    //   1. generate a keypair (inserts row)
    //   2. await closeDb() + _resetCacheForTest() — simulate process exit
    //   3. call await getOrGenerate() again — should READ the existing row,
    //      not generate a new one.
    it('reads the existing keypair after closeDb + cache reset (no regeneration)', async () => {
      const first = await getOrGenerate();
      const firstPubHex = bytesToHex(first.publicKey);
      const firstPrivHex = bytesToHex(first.privateKey);

      // Simulate process restart: close DB handle + clear in-memory cache.
      // The row persists on disk in TEST_DB_PATH.
      await closeTestDb();
      _resetCacheForTest();

      // Re-initialize schema (reopens DB, CREATE TABLE IF NOT EXISTS is a
      // no-op on the existing table).const second = await getOrGenerate();
      expect(bytesToHex(second.publicKey)).toBe(firstPubHex);
      expect(bytesToHex(second.privateKey)).toBe(firstPrivHex);
    });
  });

  describe('keypair format + self-consistency (P == x·G)', () => {
    // NOTE: this is a SELF-CONSISTENCY check of stored data, not a security
    // proof (ISOLATION §五 不变量 7). It catches DB corruption where the
    // pubkey was swapped but the private key wasn't (or vice versa).
    it('publicKey: 33 bytes, prefix 0x02/0x03, on-curve', async () => {
      const kp = await getOrGenerate();
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey.length).toBe(33);
      expect([0x02, 0x03]).toContain(kp.publicKey[0]);
      expect(isOnCurve(kp.publicKey)).toBe(true);
    });

    it('privateKey: 32 bytes, scalar ∈ [1, n-1]', async () => {
      const kp = await getOrGenerate();
      expect(kp.privateKey).toBeInstanceOf(Uint8Array);
      expect(kp.privateKey.length).toBe(32);
      const x = bytesToScalar(kp.privateKey);
      expect(isValidScalar(x)).toBe(true);   // 1 ≤ x < n
    });

    it('P == x·G (re-derive public key from private key)', async () => {
      const kp = await getOrGenerate();
      const x = bytesToScalar(kp.privateKey);
      const P = G.multiply(x);
      const PBytes = P.toRawBytes(true); // 33-byte compressed
      expect(PBytes).toStrictEqual(kp.publicKey);
    });
  });

  describe('await getPublicKey() / await getPrivateKey() accessors', () => {
    it('await getPublicKey() returns the same 33B as await getOrGenerate().publicKey', async () => {
      const kp = await getOrGenerate();
      expect(await getPublicKey()).toStrictEqual(kp.publicKey);
    });

    it('await getPrivateKey() returns the same 32B as await getOrGenerate().privateKey', async () => {
      const kp = await getOrGenerate();
      expect(await getPrivateKey()).toStrictEqual(kp.privateKey);
    });
  });

  // ────────────────────────────────────────────────────────────────────
  // Phase 3 (v5 §三 3.1 + 3.2): multi-key rotation + AES at-rest encryption
  // ────────────────────────────────────────────────────────────────────
  describe('Phase 3: AES-256-GCM at-rest encryption', () => {
    it('DB private_key is 60-byte ciphertext (nonce+ct+tag), not 32-byte plaintext', async () => {
      const kp = await getOrGenerate();
      const row = await queryOne('SELECT private_key FROM bank_keys WHERE status = ?',['active']);
      expect(row).toBeDefined();
      expect(row.private_key.length).toBe(60); // 12 + 32 + 16
      expect(new Uint8Array(row.private_key)).not.toStrictEqual(kp.privateKey);
    });

    it('await getActiveKeyVersion() returns key_version=1 on first boot', async () => {
      await getOrGenerate();
      expect(await getActiveKeyVersion()).toBe(1);
    });
  });

  describe('Phase 3: getPublicKeyByVersion — real DB lookup', () => {
    it('await getPublicKeyByVersion(1) returns the same key as await getActivePublicKey()', async () => {
      const kp = await getOrGenerate();
      const byV1 = await getPublicKeyByVersion(1);
      expect(byV1).toBeInstanceOf(Uint8Array);
      expect(byV1.length).toBe(33);
      expect(byV1).toStrictEqual(kp.publicKey);
      expect(byV1).toStrictEqual(await getActivePublicKey());
    });

    it('await getPublicKeyByVersion(999) throws BankKeyError(404 KEY_NOT_FOUND)', async () => {
      await getOrGenerate(); // ensure a key exists
      await expect(getPublicKeyByVersion(999)).rejects.toThrow(BankKeyError);
      try {
        await getPublicKeyByVersion(999);
        throw new Error('should have thrown');
      } catch (e) {
        expect(e.code).toBe('KEY_NOT_FOUND');
        expect(e.status).toBe(404);
      }
    });
  });

  describe('Phase 3: rotateKey — key rotation with 90-day grace period', () => {
    it('rotateKey marks old key retired + creates new active key_version', async () => {
      await getOrGenerate(); // key_version=1
      const result = await rotateKey(null);
      expect(result.old_version).toBe(1);
      expect(result.new_version).toBe(2);

      // Old key should be retired
      const oldKey = await queryOne(
        'SELECT status, retired_until, retired_at FROM bank_keys WHERE key_version = 1',
      );
      expect(oldKey.status).toBe('retired');
      expect(oldKey.retired_until).toBeTruthy();
      expect(oldKey.retired_at).toBeTruthy();

      // New key should be active
      const newKey = await queryOne(
        'SELECT status, key_version FROM bank_keys WHERE key_version = 2',
      );
      expect(newKey.status).toBe('active');
      expect(newKey.key_version).toBe(2);

      // Active key version should now be 2
      expect(await getActiveKeyVersion()).toBe(2);
    });

    it('after rotation, old token (key_id=1) can still be verified (grace period)', async () => {
      const kp1 = await getOrGenerate(); // v1
      await rotateKey(null); // → v2

      // Old token with key_id=1 should still verify — await getPublicKeyByVersion(1)
      // returns the old public key (retired but within grace period).
      _resetCacheForTest(); // force DB reload
      const oldPub = await getPublicKeyByVersion(1);
      expect(oldPub).toStrictEqual(kp1.publicKey);
    });

    it('after rotation, new token uses key_id=2 (getActiveKeyVersion)', async () => {
      await getOrGenerate(); // v1
      await rotateKey(null); // → v2
      expect(await getActiveKeyVersion()).toBe(2);

      const activePub = await getActivePublicKey();
      const v2Pub = await getPublicKeyByVersion(2);
      expect(activePub).toStrictEqual(v2Pub);
    });

    it('retired_until expiry → getPublicKeyByVersion throws BankKeyError(403 KEY_RETIRED)', async () => {
      await getOrGenerate(); // v1
      await rotateKey(null); // v1 retired

      // Manually set retired_until to the past to simulate expiry
      await runWrite(
        `UPDATE bank_keys SET retired_until = NOW() - INTERVAL '1 day'
         WHERE key_version = 1`,
      );
      _resetCacheForTest(); // clear version cache

      await expect(getPublicKeyByVersion(1)).rejects.toThrow(BankKeyError);
      try {
        await getPublicKeyByVersion(1);
        throw new Error('should have thrown');
      } catch (e) {
        expect(e.code).toBe('KEY_RETIRED');
        expect(e.status).toBe(403);
      }
    });
  });
});

describe('M3 · GET /api/bank/pubkey — public key endpoint (no auth)', () => {
  // Pre-populate the cache + DB row so the route handler returns from cache.
  // (The route calls await getPublicKey() which lazily calls await getOrGenerate() if
  // cache is empty — but we want a deterministic key for the assertions.)
  let cachedPubHex;
  beforeEach(async () => {
    const kp = await getOrGenerate();
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
