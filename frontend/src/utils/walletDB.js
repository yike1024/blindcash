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
// 依赖：idb（Jake Archibald 维护的 IndexedDB promise 封装，~1.2KB）。

import { openDB } from 'idb';

const DB_NAME = 'blindcash-wallet';
const DB_VERSION = 1;
const STORE = 'coins';

/**
 * Token v2 schema (Phase 1 §三 1.7):
 *   { serial(64hex), amount, R_prime(66hex), s_prime(64hex), key_id, created_at }
 */

// Singleton DB promise — openDB is called once and reused.
let dbPromise = null;

function getDb() {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE)) {
          const store = db.createObjectStore(STORE, { keyPath: 'serial' });
          store.createIndex('created_at', 'created_at', { unique: false });
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

// Export for tests to reset the singleton between test files.
export function _resetDbForTest() {
  dbPromise = null;
}
