// services/bankKeyService.js — M3/Phase 3: bank signing keypair persistence (PostgreSQL)
//
// All DB operations are now async (pg). In-memory caches (_activeCache,
// _versionCache) remain synchronous; only the DB reads/writes are awaited.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { getDb, queryOne, runWrite, runImmediateTx } from '../models/db.js';
import { generateKeyPair } from '../crypto/server/schnorrBlind.js';
import {
  G,
  n,
  isOnCurve,
  bytesToScalar,
  isValidScalar,
} from '../crypto/server/curve.js';
import { MASTER_KEY, BANK_KEY_ROW_ID } from '../config/bank.js';
import { logAction } from './auditService.js';

const _masterKeyBuf = Buffer.from(MASTER_KEY, 'hex');

const CIPHERTEXT_LEN = 60;
const PLAINTEXT_LEN = 32;

export class BankKeyError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'BankKeyError';
    this.status = status;
    this.code = code;
  }
}

// ── AES-256-GCM encrypt / decrypt ──

function encryptPrivateKey(plainBytes) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', _masterKeyBuf, nonce);
  const ct = Buffer.concat([cipher.update(plainBytes), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]);
}

function decryptPrivateKey(encBlob) {
  const buf = Buffer.from(encBlob);
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', _masterKeyBuf, nonce);
  decipher.setAuthTag(tag);
  try {
    return new Uint8Array(Buffer.concat([decipher.update(ct), decipher.final()]));
  } catch {
    throw new Error(
      'bankKeyService: failed to decrypt bank_keys.private_key — ' +
      'the stored ciphertext was encrypted under a different BC_MASTER_KEY. ' +
      'Either set BC_MASTER_KEY to the same value used originally, or ' +
      'delete the database and re-bootstrap.'
    );
  }
}

function isEncrypted(blob) {
  return blob.length === CIPHERTEXT_LEN;
}

// ── In-memory caches ──
const _activeCache = new Map();
const _versionCache = new Map();

function assertKeypairConsistent(kp) {
  const { publicKey, privateKey } = kp;
  if (publicKey.length !== 33) throw new Error(`bankKeyService: public_key length ${publicKey.length} ≠ 33`);
  if (publicKey[0] !== 0x02 && publicKey[0] !== 0x03) {
    throw new Error(`bankKeyService: public_key prefix 0x${publicKey[0].toString(16)} not in {0x02,0x03}`);
  }
  if (!isOnCurve(publicKey)) throw new Error('bankKeyService: stored public_key is not on curve');
  if (privateKey.length !== 32) throw new Error(`bankKeyService: private_key length ${privateKey.length} ≠ 32`);
  const x = bytesToScalar(privateKey);
  if (!isValidScalar(x)) throw new Error('bankKeyService: stored private_key out of range [1, n-1]');
  const P = G.multiply(x);
  const PBytes = P.toRawBytes(true);
  let diff = 0;
  for (let i = 0; i < 33; i++) diff |= publicKey[i] ^ PBytes[i];
  if (diff !== 0) throw new Error('bankKeyService: stored public_key ≠ x·G — keypair inconsistent');
}

/**
 * Read the active key row for a denomination, decrypt private_key, handle
 * migration plaintext → encrypted upgrade.
 */
async function loadActiveFromDb(denom) {
  const row = await queryOne(
    `SELECT key_version, public_key, private_key FROM bank_keys
     WHERE status = 'active' AND denomination = ?
     ORDER BY key_version DESC LIMIT 1`,
    [denom],
  );
  if (!row) return null;

  const publicKey = new Uint8Array(row.public_key);

  let privateKey;
  if (isEncrypted(row.private_key)) {
    privateKey = decryptPrivateKey(row.private_key);
  } else if (row.private_key.length === PLAINTEXT_LEN) {
    privateKey = new Uint8Array(row.private_key);
    const encBlob = encryptPrivateKey(privateKey);
    await runWrite(
      `UPDATE bank_keys SET private_key = ? WHERE key_version = ?`,
      [encBlob, row.key_version],
    );
  } else {
    throw new Error(
      `bankKeyService: private_key blob length ${row.private_key.length} ` +
      `is neither plaintext(32) nor ciphertext(60) — DB corrupted`,
    );
  }

  return { publicKey, privateKey, key_version: row.key_version, denomination: denom };
}

/**
 * Get the active bank keypair for a denomination, generating + persisting
 * it on first boot. Idempotent.
 * @returns {Promise<{publicKey, privateKey, key_version, denomination}>}
 */
export async function getOrGenerate(denom = 1) {
  if (_activeCache.has(denom)) return _activeCache.get(denom);

  let kp = await loadActiveFromDb(denom);

  if (!kp) {
    const fresh = generateKeyPair();
    const encBlob = encryptPrivateKey(fresh.privateKey);

    // 在单连接事务内执行 MAX(key_version)+INSERT：
    // 并发首次启动时，pg_advisory_xact_lock 把"取最大值→写新行"
    // 序列化为临界区，防止两个进程拿到相同 key_version 撞 UNIQUE。
    const newVersion = await runImmediateTx(async (db) => {
      // 固定 advisory lock id（bank_keys 单表命名空间）。
      await db.prepare(`SELECT pg_advisory_xact_lock(?)`).get(424242);
      const maxRow = await db.prepare(
        `SELECT COALESCE(MAX(key_version), 0) AS mv FROM bank_keys`,
      ).get();
      const nv = (maxRow?.mv ?? 0) + 1;
      await db.prepare(
        `INSERT INTO bank_keys (key_version, denomination, public_key, private_key, status)
         VALUES (?, ?, ?, ?, 'active')`,
      ).run(nv, denom, Buffer.from(fresh.publicKey), encBlob);
      return nv;
    });
    kp = { publicKey: fresh.publicKey, privateKey: fresh.privateKey, key_version: newVersion, denomination: denom };
  } else {
    assertKeypairConsistent(kp);
  }

  _activeCache.set(denom, kp);
  return kp;
}

export async function getPublicKey() {
  return (await getOrGenerate(1)).publicKey;
}

export async function getActivePublicKey() {
  return (await getOrGenerate(1)).publicKey;
}

export async function getActiveKeyVersion() {
  return (await getOrGenerate(1)).key_version;
}

export async function getActivePublicKeyByDenom(denom) {
  return (await getOrGenerate(denom)).publicKey;
}

export async function getActiveKeyVersionByDenom(denom) {
  return (await getOrGenerate(denom)).key_version;
}

export async function getPrivateKeyByDenom(denom = 1) {
  return (await getOrGenerate(denom)).privateKey;
}

/**
 * Get a historical bank public key by key_version.
 * @throws {BankKeyError} 403 KEY_RETIRED / 404 KEY_NOT_FOUND
 */
export async function getPublicKeyByVersion(v) {
  if (_versionCache.has(v)) {
    const cached = _versionCache.get(v);
    checkRetired(cached, v);
    return cached.publicKey;
  }

  const row = await queryOne(
    `SELECT public_key, private_key, status, retired_until, denomination
     FROM bank_keys WHERE key_version = ?`,
    [v],
  );

  if (!row) {
    throw new BankKeyError(404, 'KEY_NOT_FOUND',
      `unknown key_version ${v} — token was signed by a key this bank does not know`);
  }

  let privateKey;
  if (isEncrypted(row.private_key)) {
    privateKey = decryptPrivateKey(row.private_key);
  } else if (row.private_key.length === PLAINTEXT_LEN) {
    privateKey = new Uint8Array(row.private_key);
    const encBlob = encryptPrivateKey(privateKey);
    await runWrite(
      `UPDATE bank_keys SET private_key = ? WHERE key_version = ?`,
      [encBlob, v],
    );
  } else {
    throw new Error(`bankKeyService: private_key blob length ${row.private_key.length} corrupted`);
  }

  const entry = {
    publicKey: new Uint8Array(row.public_key),
    privateKey,
    status: row.status,
    retired_until: row.retired_until,
    denomination: row.denomination ?? 1,
  };
  _versionCache.set(v, entry);

  checkRetired(entry, v);
  return entry.publicKey;
}

export async function getDenominationByVersion(v) {
  if (_versionCache.has(v)) {
    return _versionCache.get(v).denomination ?? 1;
  }
  const row = await queryOne(
    `SELECT denomination FROM bank_keys WHERE key_version = ?`,
    [v],
  );
  if (!row) {
    throw new BankKeyError(404, 'KEY_NOT_FOUND', `unknown key_version ${v}`);
  }
  return row.denomination ?? 1;
}

function checkRetired(entry, v) {
  if (entry.status === 'retired' && entry.retired_until) {
    const until = new Date(entry.retired_until).getTime();
    if (Date.now() > until) {
      throw new BankKeyError(403, 'KEY_RETIRED',
        `key_version ${v} is retired and past its grace period ` +
        `(retired_until ${entry.retired_until}) — tokens from this key are no longer honored`);
    }
  }
}

export async function getPrivateKey() {
  return (await getOrGenerate(1)).privateKey;
}

/**
 * Rotate the bank signing key for a denomination.
 * @returns {Promise<{old_version, new_version, denomination}>}
 */
export async function rotateKey(denom = 1, actorId) {
  if (!Number.isInteger(denom) || denom <= 0) {
    actorId = denom;
    denom = 1;
  }
  const current = await getOrGenerate(denom);
  const oldVersion = current.key_version;

  const now = new Date();
  const retiredUntil = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  const nowIso = now.toISOString().replace('T', ' ').slice(0, 19);
  const untilIso = retiredUntil.toISOString().replace('T', ' ').slice(0, 19);

  const fresh = generateKeyPair();
  const encBlob = encryptPrivateKey(fresh.privateKey);

  const newVersion = await runImmediateTx(async (db) => {
    await db.prepare(
      `UPDATE bank_keys
          SET status = 'retired',
              retired_at = ?,
              retired_until = ?
        WHERE key_version = ? AND status = 'active'`,
    ).run(nowIso, untilIso, oldVersion);

    const maxRow = await db.prepare(
      `SELECT COALESCE(MAX(key_version), 0) AS mv FROM bank_keys`,
    ).get();
    const nv = (maxRow?.mv ?? 0) + 1;

    await db.prepare(
      `INSERT INTO bank_keys (key_version, denomination, public_key, private_key, status)
       VALUES (?, ?, ?, ?, 'active')`,
    ).run(nv, denom, Buffer.from(fresh.publicKey), encBlob);

    return nv;
  });

  _activeCache.delete(denom);
  _versionCache.delete(oldVersion);

  await logAction({
    actor_id: actorId ?? null,
    action: 'key_rotate',
    target: `denom${denom}:v${oldVersion}→v${newVersion}`,
    meta: JSON.stringify({ denomination: denom, old_version: oldVersion, new_version: newVersion, retired_until: untilIso }),
  });

  return { old_version: oldVersion, new_version: newVersion, denomination: denom };
}

export function _resetCacheForTest() {
  _activeCache.clear();
  _versionCache.clear();
}
