// utils/walletDB.js — Phase 2: 客户端 IndexedDB 钱包
//
// v5 §三 Phase 2 方案 A：钱包在客户端 IndexedDB，后端无 wallet 表、无
// /api/wallet/* 接口（L1 修正：否则银行可关联 serial → 用户身份，摧毁匿名性）。
//
// **XSS 威胁模型（m6 修正，见 docs/DESIGN.md）**：
//   IndexedDB 无加密，token 明文躺浏览器。XSS 可一锅端。教学系统可接受
//   （无外部攻击面），生产环境应加密存储或用 WebCrypto API 派生密钥。
//
// **为什么不用 sessionStorage**：关标签页烧钱——token 只在当前标签页存活，
//   用户关页即丢失。IndexedDB 持久化到浏览器，关页重开 token 仍在。
//
// **serial 做 keyPath**：天然 PRIMARY KEY，重复存入同一 serial 会触发
//   ConstraintError——防重复存入（同一 token 存两次没意义）。
//
// Phase 6.4 (v6 §四 6.4)：新增 pending_payments store。网络故障时支付请求
// 暂存于此，待网络恢复后用户可手动重试。与 coins store 隔离——pending
// 的 token 仍在钱包里（未消费），重试成功后才从 coins 删除。
//
// 依赖：idb（Jake Archibald 维护的 IndexedDB promise 封装，~1.2KB）。

import { openDB } from 'idb';

const DB_NAME = 'blindcash-wallet';
const DB_VERSION = 2;
const STORE = 'coins';
const PENDING_STORE = 'pending_payments';

/**
 * Token v2 schema (Phase 1 §三 1.7):
 *   { serial(64hex), amount, R_prime(66hex), s_prime(64hex), key_id, created_at }
 *
 * Pending payment record (Phase 6.4):
 *   { id(auto), token, created_at, attempts, last_error }
 *   token = { serial, amount, R_prime, s_prime, key_id } — 原样存副本
 */

// Singleton DB promise — openDB is called once and reused.
let dbPromise = null;

function getDb() {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db, oldVersion) {
        // v1: coins store
        if (oldVersion < 1) {
          if (!db.objectStoreNames.contains(STORE)) {
            const store = db.createObjectStore(STORE, { keyPath: 'serial' });
            store.createIndex('created_at', 'created_at', { unique: false });
          }
        }
        // v2 (Phase 6.4): pending_payments store
        if (oldVersion < 2) {
          if (!db.objectStoreNames.contains(PENDING_STORE)) {
            const pStore = db.createObjectStore(PENDING_STORE, {
              keyPath: 'id',
              autoIncrement: true,
            });
            pStore.createIndex('created_at', 'created_at', { unique: false });
          }
        }
      },
    });
  }
  return dbPromise;
}

/**
 * Validate required token fields before persisting.
 * 审查建议 5：防止未来有人绕过 UI 直接调 API 存半个 token 进去。
 * @param {object} coin
 * @throws {Error} if required fields missing
 */
function validateCoin(coin) {
  if (!coin || typeof coin !== 'object') {
    throw new Error('coin must be an object');
  }
  if (typeof coin.serial !== 'string' || coin.serial.length !== 64) {
    throw new Error('serial must be a 64-char hex string');
  }
  if (!Number.isInteger(coin.amount) || coin.amount <= 0) {
    throw new Error('amount must be a positive integer');
  }
  if (typeof coin.R_prime !== 'string' || coin.R_prime.length !== 66) {
    throw new Error('R_prime must be a 66-char hex string (compressed point)');
  }
  if (typeof coin.s_prime !== 'string' || coin.s_prime.length !== 64) {
    throw new Error('s_prime must be a 64-char hex string');
  }
}

/**
 * Store a coin in the wallet. Rejects if a coin with the same serial already
 * exists (ConstraintError from keyPath uniqueness).
 *
 * @param {{serial:string, amount:number, R_prime:string, s_prime:string, key_id?:number}} coin
 * @returns {Promise<void>}
 * @throws {Error} on validation failure or duplicate serial
 */
export async function putCoin(coin) {
  validateCoin(coin);
  const db = await getDb();
  const record = {
    ...coin,
    created_at: coin.created_at ?? Date.now(),
  };
  // add() throws ConstraintError if keyPath already exists — we WANT that
  // (no duplicate tokens in wallet).
  await db.add(STORE, record);
}

/**
 * Get a coin by serial.
 * @param {string} serial
 * @returns {Promise<object|undefined>}
 */
export async function getCoin(serial) {
  const db = await getDb();
  return db.get(STORE, serial);
}

/**
 * List all coins, sorted by created_at descending (newest first).
 * @returns {Promise<object[]>}
 */
export async function listCoins() {
  const db = await getDb();
  const all = await db.getAll(STORE);
  return all.sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0));
}

/**
 * Delete a coin by serial. No-op if the coin doesn't exist.
 * @param {string} serial
 * @returns {Promise<void>}
 */
export async function deleteCoin(serial) {
  const db = await getDb();
  await db.delete(STORE, serial);
}

/**
 * Check if a coin with the given serial exists in the wallet.
 * @param {string} serial
 * @returns {Promise<boolean>}
 */
export async function hasCoin(serial) {
  const db = await getDb();
  const count = await db.count(STORE, serial);
  return count > 0;
}

/**
 * Clear the entire wallet. Primarily for testing / debugging.
 * @returns {Promise<void>}
 */
export async function clearAll() {
  const db = await getDb();
  await db.clear(STORE);
}

/**
 * Total balance of all coins in the wallet (sum of amounts).
 * @returns {Promise<number>}
 */
export async function totalBalance() {
  const coins = await listCoins();
  return coins.reduce((sum, c) => sum + (c.amount ?? 0), 0);
}

// ───────────────────────────────────────────────────────────────
// Phase 6.4: pending_payments — 离线支付暂存与重试
// ───────────────────────────────────────────────────────────────

/**
 * Queue a payment for later retry. Called when /payment fails due to
 * network error or 5xx server error (NOT for 4xx permanent failures like
 * SIGNATURE_INVALID or DOUBLE_SPEND — those are handled differently).
 *
 * The token is stored as a COPY so that deleting it from the coins store
 * (on successful retry or DOUBLE_SPEND confirmation) doesn't destroy the
 * retry record.
 *
 * @param {{serial:string, amount:number, R_prime:string, s_prime:string, key_id?:number}} token
 * @param {string} errorMsg — human-readable error from the failed attempt
 * @returns {Promise<number>} the auto-assigned pending payment id
 */
export async function addPendingPayment(token, errorMsg) {
  const db = await getDb();
  const record = {
    token: { ...token }, // shallow copy — detach from caller's reference
    created_at: Date.now(),
    attempts: 0,
    last_error: errorMsg ?? 'unknown error',
  };
  const id = await db.add(PENDING_STORE, record);
  return id;
}

/**
 * List all pending payments, sorted by created_at ascending (oldest first
 * — oldest should be retried first).
 * @returns {Promise<Array<{id:number, token:object, created_at:number, attempts:number, last_error:string}>>}
 */
export async function listPendingPayments() {
  const db = await getDb();
  const all = await db.getAll(PENDING_STORE);
  return all.sort((a, b) => (a.created_at ?? 0) - (b.created_at ?? 0));
}

/**
 * Delete a pending payment by id (after successful retry or permanent
 * failure confirmation like DOUBLE_SPEND).
 * @param {number} id
 * @returns {Promise<void>}
 */
export async function deletePendingPayment(id) {
  const db = await getDb();
  await db.delete(PENDING_STORE, id);
}

/**
 * Increment the attempts counter and update last_error for a pending payment.
 * Called after each retry attempt (success or failure).
 *
 * @param {number} id
 * @param {string} errorMsg — empty string clears the error on success
 * @returns {Promise<void>}
 */
export async function updatePendingPaymentAttempt(id, errorMsg) {
  const db = await getDb();
  const record = await db.get(PENDING_STORE, id);
  if (!record) return;
  record.attempts = (record.attempts ?? 0) + 1;
  record.last_error = errorMsg ?? '';
  await db.put(PENDING_STORE, record);
}

/**
 * Count pending payments — used for the Dashboard badge.
 * @returns {Promise<number>}
 */
export async function countPendingPayments() {
  const db = await getDb();
  return db.count(PENDING_STORE);
}

/**
 * Clear all pending payments. Primarily for testing / debugging.
 * @returns {Promise<void>}
 */
export async function clearAllPending() {
  const db = await getDb();
  await db.clear(PENDING_STORE);
}

// Export for tests to reset the singleton between test files.
export function _resetDbForTest() {
  dbPromise = null;
}
