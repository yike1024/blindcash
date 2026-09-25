// tests/multiDenomination.test.js — Phase 6.1: 多面额密钥
//
// 测试矩阵:
//   ✓ 不同面额生成独立的密钥对（publicKey 不同）
//   ✓ await getActivePublicKeyByDenom(denom) 返回正确的公钥
//   ✓ await getActiveKeyVersionByDenom(denom) 返回不同的 key_version
//   ✓ await getDenominationByVersion(v) 正确反查 denom
//   ✓ bank_keys 表 partial unique index 保证每个面额只有一个 active
//   ✓ await rotateKey(denom) 按面额轮换，不影响其他面额
//   ✓ /api/bank/pubkeys 返回所有面额的公钥映射

import { describe, it, expect, beforeEach, afterEach, afterAll } from 'vitest';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';

import {
  getOrGenerate,
  getActivePublicKey,
  getActiveKeyVersion,
  getActivePublicKeyByDenom,
  getActiveKeyVersionByDenom,
  getPrivateKeyByDenom,
  getDenominationByVersion,
  rotateKey,
  _resetCacheForTest,
} from '../src/services/bankKeyService.js';
import { getDb, closeDb, queryOne } from '../src/models/db.js';
import { resetTestDb, ensureDatabaseUrl, closeTestDb } from './helpers/testDb.js';
import { bytesToHex } from '../src/utils/hex.js';
import app from '../src/app.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
ensureDatabaseUrl();
beforeEach(async () => {
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

describe('Phase 6.1 · multi-denomination keys', () => {
  it('different denominations get independent keypairs', async () => {
    const kp1 = await getOrGenerate(1);
    const kp5 = await getOrGenerate(5);
    const kp10 = await getOrGenerate(10);

    // Public keys must be different across denominations
    expect(kp1.publicKey).not.toStrictEqual(kp5.publicKey);
    expect(kp5.publicKey).not.toStrictEqual(kp10.publicKey);
    expect(kp1.publicKey).not.toStrictEqual(kp10.publicKey);

    // key_versions must be different (globally unique)
    expect(kp1.key_version).not.toBe(kp5.key_version);
    expect(kp5.key_version).not.toBe(kp10.key_version);

    // Each should have denomination field
    expect(kp1.denomination).toBe(1);
    expect(kp5.denomination).toBe(5);
    expect(kp10.denomination).toBe(10);
  });

  it('getActivePublicKeyByDenom returns correct key per denom', async () => {
    const pk1 = await getActivePublicKeyByDenom(1);
    const pk5 = await getActivePublicKeyByDenom(5);

    // Should be 33-byte compressed points
    expect(pk1.length).toBe(33);
    expect(pk5.length).toBe(33);
    // Compressed point prefix: 0x02 or 0x03
    expect([2, 3]).toContain(pk1[0]);
    expect([2, 3]).toContain(pk5[0]);

    // Must be different
    expect(pk1).not.toStrictEqual(pk5);
  });

  it('getActiveKeyVersionByDenom returns different versions per denom', async () => {
    const kv1 = await getActiveKeyVersionByDenom(1);
    const kv5 = await getActiveKeyVersionByDenom(5);
    const kv10 = await getActiveKeyVersionByDenom(10);

    expect(kv1).not.toBe(kv5);
    expect(kv5).not.toBe(kv10);
    expect(kv1).not.toBe(kv10);
  });

  it('getDenominationByVersion reverse-looks-up denom from key_version', async () => {
    const kp1 = await getOrGenerate(1);
    const kp5 = await getOrGenerate(5);

    expect(await getDenominationByVersion(kp1.key_version)).toBe(1);
    expect(await getDenominationByVersion(kp5.key_version)).toBe(5);
  });

  it('default await getOrGenerate() uses denom=1 (backward compat)', async () => {
    const kpDefault = await getOrGenerate();     // no arg → denom=1
    const kp1 = await getOrGenerate(1);

    expect(kpDefault.key_version).toBe(kp1.key_version);
    expect(kpDefault.publicKey).toStrictEqual(kp1.publicKey);
    expect(kpDefault.denomination).toBe(1);
  });

  it('getActivePublicKey/getActiveKeyVersion are denom=1 aliases', async () => {
    await getOrGenerate(1);
    await getOrGenerate(5); // ensure denom=5 exists too

    const pkAlias = await getActivePublicKey();
    const pk1 = await getActivePublicKeyByDenom(1);
    expect(pkAlias).toStrictEqual(pk1);

    const kvAlias = await getActiveKeyVersion();
    const kv1 = await getActiveKeyVersionByDenom(1);
    expect(kvAlias).toBe(kv1);
  });

  it('bank_keys has exactly one active key per denomination (partial unique index)', async () => {
    await getOrGenerate(1);
    await getOrGenerate(5);

    const activeCount1 = await queryOne(
      `SELECT COUNT(*) AS c FROM bank_keys WHERE denomination = 1 AND status = 'active'`,
    );
    expect(activeCount1.c).toBe(1);

    const activeCount5 = await queryOne(
      `SELECT COUNT(*) AS c FROM bank_keys WHERE denomination = 5 AND status = 'active'`,
    );
    expect(activeCount5.c).toBe(1);
  });

  it('await rotateKey(denom) rotates only that denom, not others', async () => {
    const kp1Before = await getOrGenerate(1);
    const kp5Before = await getOrGenerate(5);

    // Rotate denom=1 only
    const result = await rotateKey(1, null);

    expect(result.denomination).toBe(1);
    expect(result.old_version).toBe(kp1Before.key_version);
    expect(result.new_version).not.toBe(kp1Before.key_version);

    // Denom 5 should be unchanged
    const kv5After = await getActiveKeyVersionByDenom(5);
    expect(kv5After).toBe(kp5Before.key_version);

    // Denom 1 should have a new key_version
    const kv1After = await getActiveKeyVersionByDenom(1);
    expect(kv1After).not.toBe(kp1Before.key_version);
    expect(kv1After).toBe(result.new_version);

    // Old denom=1 key should be retired
    const oldRow = await queryOne(
      `SELECT status FROM bank_keys WHERE key_version = ?`,
      [kp1Before.key_version],
    );
    expect(oldRow.status).toBe('retired');
  });

  it('GET /api/bank/pubkeys returns all denominations', async () => {
    // Generate keys for some denoms
    await getOrGenerate(1);
    await getOrGenerate(5);

    const res = await request(app).get('/api/bank/pubkeys');

    expect(res.status).toBe(200);
    expect(res.body.encoding).toBe('secp256k1-compressed');
    expect(res.body.byte_length).toBe(33);
    expect(res.body.denominations).toBeDefined();

    // Denom 1 and 5 should be present
    expect(res.body.denominations['1']).toBeDefined();
    expect(res.body.denominations['1'].public_key).toMatch(/^[0-9a-f]{66}$/);
    expect(res.body.denominations['1'].key_id).toBeTypeOf('number');

    expect(res.body.denominations['5']).toBeDefined();
    expect(res.body.denominations['5'].public_key).toMatch(/^[0-9a-f]{66}$/);

    // Different denoms should have different public keys
    expect(res.body.denominations['1'].public_key)
      .not.toBe(res.body.denominations['5'].public_key);

    // No private key fields should leak
    const bodyStr = JSON.stringify(res.body);
    expect(bodyStr.toLowerCase()).not.toContain('private');
  });

  it('GET /api/bank/pubkey still works as denom=1 alias (backward compat)', async () => {
    await getOrGenerate(1);

    const res = await request(app).get('/api/bank/pubkey');

    expect(res.status).toBe(200);
    expect(res.body.public_key).toMatch(/^[0-9a-f]{66}$/);
    expect(res.body.key_id).toBeTypeOf('number');
  });

  it('getPrivateKeyByDenom returns 32-byte private key per denom', async () => {
    await getOrGenerate(1);
    await getOrGenerate(5);

    const sk1 = await getPrivateKeyByDenom(1);
    const sk5 = await getPrivateKeyByDenom(5);

    expect(sk1.length).toBe(32);
    expect(sk5.length).toBe(32);
    // Private keys should be different across denoms
    expect(sk1).not.toStrictEqual(sk5);
  });
});
