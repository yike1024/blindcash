// services/bankKeyService.js — M3/Phase 3: bank signing keypair persistence
//
// Phase 3 (v5 §三 3.1 + 3.2) 落地：
//   3.1 私钥 AES-256-GCM 加密存储（at-rest encryption）
//   3.2 密钥轮换（多行 bank_keys 表 + rotateKey + getPublicKeyByVersion）
//
// ⚠ ISOLATION.md §五 不变量 7: private_key 用 AES-256-GCM 加密后存 DB。
//   at-rest encryption 只防 DB 文件泄露，不防服务器进程被控（运行时密钥
//   必然在内存明文）。真实 HSM 是签名不出设备，本系统未实现 HSM。
//   测试不应依赖读 private_key 证明任何事（密钥安全是独立维度）。
//   getPrivateKey() ONLY for withdrawalService signing path, NEVER HTTP.
//
// Surface:
//   getOrGenerate()        → { publicKey, privateKey, key_version }
//                             idempotent; safe to call on every boot
//   getPublicKey()          → Uint8Array(33) — backward-compat alias
//   getActivePublicKey()   → Uint8Array(33) — current status='active' key
//   getActiveKeyVersion()   → number — active key's key_version
//   getPublicKeyByVersion(v) → Uint8Array(33) — historical key for old token verify
//   getPrivateKey()        → Uint8Array(32) — internal only
//   rotateKey()             → { old_version, new_version } — 密钥轮换
//
// AES-256-GCM format:
//   DB private_key BLOB = nonce(12) + ciphertext(32) + tag(16) = 60 bytes
//   迁移期明文 = 32 bytes（005 迁移拷贝旧明文，首次启动时检测并加密回写）

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

// Master key as 32-byte Buffer for AES-256-GCM
const _masterKeyBuf = Buffer.from(MASTER_KEY, 'hex');

// AES ciphertext total length: nonce(12) + plaintext(32) + tag(16) = 60
const CIPHERTEXT_LEN = 60;
const PLAINTEXT_LEN = 32;

/**
 * Error carrying an HTTP status, thrown by bankKeyService for key lookup
 * failures (e.g. KEY_RETIRED). Callers (paymentService) catch and map.
 */
export class BankKeyError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'BankKeyError';
    this.status = status;
    this.code = code;
  }
}

// ── AES-256-GCM encrypt / decrypt ──

/**
 * Encrypt a 32-byte private key with AES-256-GCM.
 * @param {Uint8Array|Buffer} plainBytes — 32 bytes
 * @returns {Buffer} nonce(12) + ciphertext(32) + tag(16) = 60 bytes
 */
function encryptPrivateKey(plainBytes) {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', _masterKeyBuf, nonce);
  const ct = Buffer.concat([cipher.update(plainBytes), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]); // 60 bytes
}

/**
 * Decrypt an AES-256-GCM ciphertext blob back to the 32-byte private key.
 * @param {Uint8Array|Buffer} encBlob — 60 bytes (nonce + ct + tag)
 * @returns {Uint8Array} 32 bytes
 */
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
      'This usually means BC_MASTER_KEY is unset (ephemeral key) but the DB ' +
      'was written by a previous run. Either (a) set BC_MASTER_KEY to the ' +
      'same 64-hex value used originally, or (b) delete the dev database ' +
      'and re-bootstrap.'
    );
  }
}

/**
 * Check if a stored private_key blob is encrypted (60 bytes) or plaintext
 * (32 bytes, from 005 migration copy).
 */
function isEncrypted(blob) {
  return blob.length === CIPHERTEXT_LEN;
}

// ── In-memory caches ──

// Active key cache: Map<denom, { publicKey, privateKey, key_version, denomination }>
// Phase 6.1: 每个面额有独立的 active 密钥，缓存按 denom 分桶。
// 旧代码 getPublicKey()/getActivePublicKey() 等无参函数默认走 denom=1。
const _activeCache = new Map();

// Version cache: Map<key_version, { publicKey, privateKey, status, retired_until, denomination }>
const _versionCache = new Map();

/**
 * Validate a keypair's internal consistency before trusting it.
 * Re-derive P = x·G from the stored private key and confirm it matches
 * the stored public key. Catches DB corruption/tampering.
 *
 * NOTE: self-check of stored data, NOT a protocol security proof
 * (ISOLATION §五 不变量 7).
 */
function assertKeypairConsistent(kp) {
  const { publicKey, privateKey } = kp;

  if (publicKey.length !== 33) {
    throw new Error(`bankKeyService: public_key length ${publicKey.length} ≠ 33`);
  }
  if (publicKey[0] !== 0x02 && publicKey[0] !== 0x03) {
    throw new Error(`bankKeyService: public_key prefix 0x${publicKey[0].toString(16)} not in {0x02,0x03}`);
  }
  if (!isOnCurve(publicKey)) {
    throw new Error('bankKeyService: stored public_key is not on curve');
  }
  if (privateKey.length !== 32) {
    throw new Error(`bankKeyService: private_key length ${privateKey.length} ≠ 32`);
  }
  const x = bytesToScalar(privateKey);
  if (!isValidScalar(x)) {
    throw new Error('bankKeyService: stored private_key out of range [1, n-1]');
  }
  const P = G.multiply(x);
  const PBytes = P.toRawBytes(true);
  let diff = 0;
  for (let i = 0; i < 33; i++) diff |= publicKey[i] ^ PBytes[i];
  if (diff !== 0) {
    throw new Error('bankKeyService: stored public_key ≠ x·G — keypair inconsistent');
  }
}

/**
 * Read the active key row from DB for a given denomination, decrypt
 * private_key, handle migration plaintext → encrypted upgrade.
 *
 * Phase 6.1: 每个 denom 有独立的 active 密钥行。
 *
 * @param {number} denom — denomination (1, 5, 10, 50, 100)
 * @returns {{publicKey:Uint8Array, privateKey:Uint8Array, key_version:number, denomination:number}|null}
 */
function loadActiveFromDb(denom) {
  const row = queryOne(
    `SELECT key_version, public_key, private_key FROM bank_keys
     WHERE status = 'active' AND denomination = ?
     ORDER BY key_version DESC LIMIT 1`,
    [denom],
  );
  if (!row) return null;

  const publicKey = new Uint8Array(row.public_key);

  let privateKey;
  if (isEncrypted(row.private_key)) {
    // Already encrypted — decrypt with MASTER_KEY
    privateKey = decryptPrivateKey(row.private_key);
  } else if (row.private_key.length === PLAINTEXT_LEN) {
    // Migration legacy: 005 copied old plaintext private_key. Encrypt it
    // and UPDATE the row so subsequent boots read ciphertext directly.
    privateKey = new Uint8Array(row.private_key);
    const encBlob = encryptPrivateKey(privateKey);
    runWrite(
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
 * it on first boot. Idempotent: subsequent calls return the same keypair
 * from cache.
 *
 * Phase 6.1: 每个 denom 有独立的 active 密钥行。第一次调用某 denom 时
 * 如果 DB 没有该 denom 的 active 密钥，自动生成 + 加密 + 持久化。
 *
 * Phase 3: reads status='active' row. If none, generates a new keypair,
 * AES-encrypts the private key, and INSERTs with key_version = max+1.
 *
 * @param {number} [denom=1] — denomination (1, 5, 10, 50, 100)
 * @returns {{publicKey: Uint8Array, privateKey: Uint8Array, key_version: number, denomination: number}}
 * @throws {Error} if stored keypair fails consistency self-check
 */
export function getOrGenerate(denom = 1) {
  if (_activeCache.has(denom)) return _activeCache.get(denom);

  let kp = loadActiveFromDb(denom);

  if (!kp) {
    // First boot for this denom: generate a fresh keypair, encrypt, persist.
    const fresh = generateKeyPair();
    const encBlob = encryptPrivateKey(fresh.privateKey);

    // key_version = max existing + 1 (globally unique across ALL denoms)
    const maxRow = queryOne(
      `SELECT COALESCE(MAX(key_version), 0) AS mv FROM bank_keys`,
    );
    const keyVersion = (maxRow?.mv ?? 0) + 1;

    runWrite(
      `INSERT INTO bank_keys (key_version, denomination, public_key, private_key, status)
       VALUES (?, ?, ?, ?, 'active')`,
      [keyVersion, denom, Buffer.from(fresh.publicKey), encBlob],
    );
    kp = { publicKey: fresh.publicKey, privateKey: fresh.privateKey, key_version: keyVersion, denomination: denom };
  } else {
    // Subsequent boot: verify the stored keypair is self-consistent.
    assertKeypairConsistent(kp);
  }

  _activeCache.set(denom, kp);
  return kp;
}

/**
 * Get the bank public key (33-byte compressed P = x·G).
 * Backward-compat alias for getActivePublicKey() — denom=1.
 * @returns {Uint8Array} 33 bytes
 */
export function getPublicKey() {
  return getOrGenerate(1).publicKey;
}

/**
 * Get the ACTIVE bank public key for denom=1 (33-byte compressed P = x·G).
 * 前向兼容旧调用方（paymentService fallback, bank routes /pubkey alias）。
 * @returns {Uint8Array} 33 bytes
 */
export function getActivePublicKey() {
  return getOrGenerate(1).publicKey;
}

/**
 * Get the key_version of the currently active signing key for denom=1.
 * Used by /api/bank/pubkey and withdrawalService reveal to tell clients
 * which key_version their token was signed with.
 * @returns {number}
 */
export function getActiveKeyVersion() {
  return getOrGenerate(1).key_version;
}

/**
 * Get the ACTIVE bank public key for a specific denomination.
 * Phase 6.1: 取款时按 denom 选密钥，前端需要拿到对应面额的公钥
 * 来计算盲化承诺 R' = R + α·G + β·P。
 * @param {number} denom — denomination (1, 5, 10, 50, 100)
 * @returns {Uint8Array} 33 bytes
 */
export function getActivePublicKeyByDenom(denom) {
  return getOrGenerate(denom).publicKey;
}

/**
 * Get the key_version of the currently active signing key for a denomination.
 * Phase 6.1: revealAndSign 返回的 key_id 必须是 token 对应 denom 的
 * active key_version，这样支付时 getPublicKeyByVersion(key_id) 能反查
 * 到正确的公钥验签。
 * @param {number} denom
 * @returns {number}
 */
export function getActiveKeyVersionByDenom(denom) {
  return getOrGenerate(denom).key_version;
}

/**
 * Get the bank private key for a denomination (32-byte scalar x).
 * Phase 6.1: revealAndSign 按 session.denomination 选对应密钥的私钥签名。
 * ⚠ INTERNAL ONLY — never wire to an HTTP route.
 * @param {number} [denom=1]
 * @returns {Uint8Array} 32 bytes
 */
export function getPrivateKeyByDenom(denom = 1) {
  return getOrGenerate(denom).privateKey;
}

/**
 * Get a historical bank public key by key_version. Used by paymentService
 * to verify old tokens signed before a key rotation.
 *
 * Phase 3: real DB lookup. If the key is retired and past its
 * retired_until grace period, throws BankKeyError(403, 'KEY_RETIRED')
 * — the bank no longer honors tokens from that key.
 *
 * @param {number} v — key_version (token.key_id ≡ key_version)
 * @returns {Uint8Array} 33 bytes
 * @throws {BankKeyError} 403 KEY_RETIRED if key is retired and past grace period
 * @throws {BankKeyError} 404 KEY_NOT_FOUND if v is not a known key_version
 */
export function getPublicKeyByVersion(v) {
  // Check version cache first
  if (_versionCache.has(v)) {
    const cached = _versionCache.get(v);
    checkRetired(cached, v);
    return cached.publicKey;
  }

  const row = queryOne(
    `SELECT public_key, private_key, status, retired_until, denomination
     FROM bank_keys WHERE key_version = ?`,
    [v],
  );

  if (!row) {
    throw new BankKeyError(404, 'KEY_NOT_FOUND',
      `unknown key_version ${v} — token was signed by a key this bank does not know`);
  }

  // Decrypt private key for consistency check + cache
  let privateKey;
  if (isEncrypted(row.private_key)) {
    privateKey = decryptPrivateKey(row.private_key);
  } else if (row.private_key.length === PLAINTEXT_LEN) {
    // Migration legacy plaintext — encrypt + update
    privateKey = new Uint8Array(row.private_key);
    const encBlob = encryptPrivateKey(privateKey);
    runWrite(
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
    denomination: row.denomination ?? 1, // Phase 6.1
  };
  _versionCache.set(v, entry);

  checkRetired(entry, v);
  return entry.publicKey;
}

/**
 * Get the denomination of a key by key_version. Used by paymentService
 * to record denomination in spent_coins for 6.3 anonymity set analysis.
 *
 * Phase 6.1: token 的 key_id 对应全局唯一的 key_version，由此可反查 denom。
 * 这样前端无需在 token 里带 denomination（防篡改）——服务端从 key_id 推导。
 *
 * @param {number} v — key_version
 * @returns {number} denomination
 * @throws {BankKeyError} 404 KEY_NOT_FOUND
 */
export function getDenominationByVersion(v) {
  if (_versionCache.has(v)) {
    return _versionCache.get(v).denomination ?? 1;
  }
  const row = queryOne(
    `SELECT denomination FROM bank_keys WHERE key_version = ?`,
    [v],
  );
  if (!row) {
    throw new BankKeyError(404, 'KEY_NOT_FOUND',
      `unknown key_version ${v}`);
  }
  return row.denomination ?? 1;
}

/**
 * Check if a key is retired and past its grace period.
 * @param {{status:string, retired_until:string|null}} entry
 * @param {number} v
 * @throws {BankKeyError} 403 KEY_RETIRED
 */
function checkRetired(entry, v) {
  if (entry.status === 'retired' && entry.retired_until) {
    // Q4 (Phase 2/3 验收)：retired_until 在 rotateKey() 里用
    // `toISOString().replace('T',' ').slice(0,19)` 写入，格式为
    // 'YYYY-MM-DD HH:MM:SS' 且是 UTC（toISOString 本身是 UTC）。
    // SQLite DATETIME 默认就是 UTC 无时区后缀，读取时必须补 'Z' 让
    // Date 解析为 UTC 而非本地时区。**未来如果有人改成用
    // toLocaleString() 存储就会炸——这里加 Z 是因为存储侧保证了 UTC**。
    const until = new Date(entry.retired_until + 'Z').getTime();
    if (Date.now() > until) {
      throw new BankKeyError(403, 'KEY_RETIRED',
        `key_version ${v} is retired and past its grace period ` +
        `(retired_until ${entry.retired_until}) — tokens from this key are no longer honored`);
    }
  }
}

/**
 * Get the bank private key for denom=1 (32-byte scalar x).
 * ⚠ INTERNAL ONLY — never wire to an HTTP route.
 * Phase 6.1: 多面额时用 getPrivateKeyByDenom(denom) 选对应密钥。
 * @returns {Uint8Array} 32 bytes
 */
export function getPrivateKey() {
  return getOrGenerate(1).privateKey;
}

/**
 * Rotate the bank signing key for a denomination: mark the current active
 * key as retired (with a 90-day grace period for old tokens), then generate
 * + persist a new active key with an incremented key_version.
 *
 * Phase 6.1: rotateKey 按 denom 轮换。key_version 是全局唯一的，新密钥的
 * key_version = MAX(all key_version) + 1（跨所有 denom），这样新密钥的
 * key_version 不会与任何其他 denom 的密钥冲突。
 *
 * Grace period (v5 §三 3.2): old tokens can still be verified (getPublicKeyByVersion
 * returns the old public key) for 90 days. After retired_until, verification → 403.
 *
 * @param {number} [denom=1] — denomination to rotate
 * @param {number} [actorId] — admin user id (for audit log)
 * @returns {{old_version: number, new_version: number, denomination: number}}
 */
export function rotateKey(denom = 1, actorId) {
  // 前向兼容：旧签名 rotateKey(actorId) 可能传 null 或 userId 作第一个参数。
  // 如果 denom 不是正整数，视为旧签名调用：denom=1，actorId=原参数。
  if (!Number.isInteger(denom) || denom <= 0) {
    actorId = denom;
    denom = 1;
  }
  const current = getOrGenerate(denom);
  const oldVersion = current.key_version;

  // Mark old key as retired with 90-day grace period.
  // L1 fix: all timestamps are UTC (toISOString outputs UTC). Comments
  // throughout the codebase should treat these as UTC, not server-local.
  const now = new Date();
  const retiredUntil = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  const nowIso = now.toISOString().replace('T', ' ').slice(0, 19);
  const untilIso = retiredUntil.toISOString().replace('T', ' ').slice(0, 19);

  // M1+M2 fix: wrap UPDATE (retire old) + SELECT MAX(key_version) + INSERT
  // (new active) in a SINGLE runImmediateTx so:
  //   - M1: if the process crashes between the two writes, the entire
  //     transaction rolls back — the old key stays 'active', no gap.
  //   - M2: SELECT MAX and INSERT are now in the same BEGIN IMMEDIATE,
  //     so concurrent rotateKey calls are serialized — the second one
  //     sees the first's INSERT and computes a different newVersion.
  const fresh = generateKeyPair();
  const encBlob = encryptPrivateKey(fresh.privateKey);

  const newVersion = runImmediateTx((db) => {
    // Step 1: retire old key
    db.prepare(
      `UPDATE bank_keys
          SET status = 'retired',
              retired_at = ?,
              retired_until = ?
        WHERE key_version = ? AND status = 'active'`,
    ).run(nowIso, untilIso, oldVersion);

    // Step 2: atomically compute next key_version INSIDE the same tx
    const maxRow = db.prepare(
      `SELECT COALESCE(MAX(key_version), 0) AS mv FROM bank_keys`,
    ).get();
    const nv = (maxRow?.mv ?? 0) + 1;

    // Step 3: insert new active key
    db.prepare(
      `INSERT INTO bank_keys (key_version, denomination, public_key, private_key, status)
       VALUES (?, ?, ?, ?, 'active')`,
    ).run(nv, denom, Buffer.from(fresh.publicKey), encBlob);

    return nv;
  });

  // Clear caches so subsequent calls read the new active key
  _activeCache.delete(denom);
  _versionCache.delete(oldVersion);

  // Audit log (standalone — rotateKey is called from admin route, not inside a tx)
  logAction({
    actor_id: actorId ?? null,
    action: 'key_rotate',
    target: `denom${denom}:v${oldVersion}→v${newVersion}`,
    meta: JSON.stringify({ denomination: denom, old_version: oldVersion, new_version: newVersion, retired_until: untilIso }),
  });

  return { old_version: oldVersion, new_version: newVersion, denomination: denom };
}

/**
 * Reset in-memory caches. Used by tests to force re-load from DB.
 */
export function _resetCacheForTest() {
  _activeCache.clear();
  _versionCache.clear();
}
