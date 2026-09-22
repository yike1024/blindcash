// services/bankKeyService.js — M3: bank signing keypair persistence (singleton)
//
// v3 §5 M3 step 2: bank_keys table is a singleton (CHECK(id = 1)).
// On boot, if no row exists → generate a fresh keypair via
// schnorrBlind.generateKeyPair() and INSERT id=1.
// If a row exists → read it back (do NOT regenerate — that would invalidate
// every previously-issued token).
//
// ⚠ ISOLATION.md §五 不变量 7: private_key is stored in plaintext by design
//   (教学演示用). Production should encrypt / HSM / Shamir-shard the key.
// Tests MUST NOT use read-private_key as a "proof" of any security property —
// key leakage is a separate dimension (key management), not a protocol
// property. This service exposes getPrivateKey() ONLY for use by the
// withdrawal signing path (M4 withdrawalService); it is NEVER wired to any
// HTTP route.
//
// Surface:
//   getOrGenerate()  → { publicKey: Uint8Array(33), privateKey: Uint8Array(32) }
//                       idempotent; safe to call on every boot
//   getPublicKey()    → Uint8Array(33)  (routes layer uses this for /api/bank/pubkey)
//   getPrivateKey()   → Uint8Array(32)  (internal only; M4 withdrawalService)

import { getDb, queryOne, runWrite } from '../models/db.js';
import { generateKeyPair } from '../crypto/server/schnorrBlind.js';
import {
  G,
  n,
  isOnCurve,
  bytesToScalar,
  isValidScalar,
} from '../crypto/server/curve.js';
import { BANK_KEY_ROW_ID } from '../config/bank.js';

// In-memory cache of the loaded keypair. Avoids re-reading the DB row on
// every getPublicKey()/getPrivateKey() call (the row is immutable post-boot).
let _cache = null;

/**
 * Load the bank keypair from the bank_keys singleton row.
 * @returns {{publicKey: Uint8Array, privateKey: Uint8Array}|null}
 */
function loadFromDb() {
  const row = queryOne(
    `SELECT public_key, private_key FROM bank_keys WHERE id = ?`,
    [BANK_KEY_ROW_ID],
  );
  if (!row) return null;
  // better-sqlite3 returns BLOB columns as Uint8Array (Node Buffer view).
  // Normalize to a plain Uint8Array so downstream byte-counting matches.
  const publicKey = new Uint8Array(row.public_key);
  const privateKey = new Uint8Array(row.private_key);
  return { publicKey, privateKey };
}

/**
 * Validate a keypair's internal consistency before trusting it.
 * Defensively re-derive P = x·G from the stored private key and confirm it
 * matches the stored public key. If this fails, the DB row was corrupted
 * (or tampered with) and the bank cannot sign safely — throw loudly.
 *
 * NOTE: This is a self-check of stored data, NOT a "proof" of any protocol
 * property (see ISOLATION §五 不变量 7 — reading private_key is not a proof).
 *
 * @param {{publicKey: Uint8Array, privateKey: Uint8Array}} kp
 * @throws {Error} if public_key is malformed / off-curve, private_key is out
 *         of range, or P ≠ x·G
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

  // Re-derive P = x·G from the stored private key and compare to the stored
  // public_key. This catches DB-level tampering that swapped in a different
  // pubkey while leaving the private key (or vice versa).
  const P = G.multiply(x);
  const PBytes = P.toRawBytes(true); // 33-byte compressed
  // constant-time-ish compare (lengths already equal)
  let diff = 0;
  for (let i = 0; i < 33; i++) diff |= publicKey[i] ^ PBytes[i];
  if (diff !== 0) {
    throw new Error('bankKeyService: stored public_key ≠ x·G — keypair inconsistent');
  }
}

/**
 * Get the bank keypair, generating + persisting it on first boot.
 * Idempotent: subsequent calls return the same keypair (from the same DB row).
 *
 * @returns {{publicKey: Uint8Array, privateKey: Uint8Array}}
 * @throws {Error} if the stored keypair fails the consistency self-check
 */
export function getOrGenerate() {
  if (_cache) return _cache;

  const db = getDb();
  let kp = loadFromDb();

  if (!kp) {
    // First boot: generate a fresh keypair and persist it as the singleton row.
    const fresh = generateKeyPair();
    runWrite(
      `INSERT INTO bank_keys (id, public_key, private_key) VALUES (?, ?, ?)`,
      [BANK_KEY_ROW_ID, Buffer.from(fresh.publicKey), Buffer.from(fresh.privateKey)],
    );
    kp = { publicKey: fresh.publicKey, privateKey: fresh.privateKey };
  } else {
    // Subsequent boot: verify the stored keypair is self-consistent before
    // trusting it (defensive against DB corruption/tampering).
    assertKeypairConsistent(kp);
  }

  _cache = kp;
  return kp;
}

/**
 * Get the bank public key (33-byte compressed P = x·G).
 * Routes layer uses this to serve GET /api/bank/pubkey.
 *
 * **Phase 1 (v5 §二 H2 N4)**：保留为 backward-compat alias。新代码应
 * 直接调 `getActivePublicKey()` 或 `getPublicKeyByVersion(v)`，让意图
 * 显式——Phase 3 多密钥轮换时不用改调用方。
 * @returns {Uint8Array} 33 bytes
 */
export function getPublicKey() {
  if (!_cache) getOrGenerate();
  return _cache.publicKey;
}

/**
 * Get the ACTIVE bank public key (33-byte compressed P = x·G).
 *
 * **v5 §二 H2 N4 修正**：JS 无类型，`getPublicKey(key_id?)` 重载会让
 * `getPublicKey(undefined)` 走哪条不清楚。拆成两个函数避免语义含糊：
 *   - `getActivePublicKey()` — 当前 status='active' 的密钥（用于签发新 token）
 *   - `getPublicKeyByVersion(v)` — 按 key_version 查历史公钥（用于验签旧 token）
 *
 * Phase 1 单密钥阶段两个函数返回同一个 key（key_version=1, status=active）。
 * Phase 3 加多密钥轮换时，本函数查 `bank_keys WHERE status='active'`。
 *
 * 调用方：routes/bank.js GET /api/bank/pubkey / withdrawalService 取签发密钥。
 * @returns {Uint8Array} 33 bytes
 */
export function getActivePublicKey() {
  if (!_cache) getOrGenerate();
  return _cache.publicKey;
}

/**
 * Get a historical bank public key by key_version. Used by paymentService
 * to verify old tokens signed before a key rotation.
 *
 * Phase 1 (single key): always returns the same key regardless of v.
 * Phase 3 (multi-key rotation): query `bank_keys WHERE key_version = v`.
 *
 * @param {number} v — key_version (token.key_id ≡ key_version, see H2 注释)
 * @returns {Uint8Array} 33 bytes
 * @throws {Error} if v is not a known key_version (Phase 3 will enforce;
 *         Phase 1 accepts any v since only one key exists)
 */
export function getPublicKeyByVersion(v) {
  // Phase 1: ignore v, always return the single key. Phase 3 will validate
  // v ∈ {known key_versions} and lookup from bank_keys multi-row table.
  if (!_cache) getOrGenerate();
  return _cache.publicKey;
}

/**
 * Get the bank private key (32-byte scalar x).
 *
 * ⚠ INTERNAL ONLY — never wire this to an HTTP route.
 * Used by M4 withdrawalService to compute s = (k + e·x) mod n on the
 * signed candidate. Reading x is a privileged internal operation, not a
 * security property (see ISOLATION §五 不变量 7).
 *
 * @returns {Uint8Array} 32 bytes
 */
export function getPrivateKey() {
  if (!_cache) getOrGenerate();
  return _cache.privateKey;
}

/**
 * Reset the in-memory cache. Used by tests to force a re-load from DB
 * (simulating a fresh process boot against the same DB file).
 */
export function _resetCacheForTest() {
  _cache = null;
}
