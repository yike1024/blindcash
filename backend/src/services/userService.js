// services/userService.js — M1: user (pseudonym) CRUD with role
//
// users table columns: id, username (UNIQUE), password_hash, role, balance, created_at
// (M1: role + balance added on top of the cryptobank userService pattern)
//
// We store only the bcrypt hash of the password. The plaintext never touches
// the database. Role is immutable after registration (enforced by API: no
// update-role endpoint).
//
// M5 addition: registering as a 'customer' initializes balance to
// INITIAL_BALANCE_CUSTOMER. v5 Phase 1 (1.5 开户改革)：改为 0，新用户必须
// 先充值才能取款——模拟真实 eCash 的"法币入账 → 电子币出账"流程，
// 不再教学性赠送 100 BC。测试改造用 fundUser(id, amount) helper 充值。
//
// ISOLATION.md §一 explicitly notes balance initialization path:
// Phase 1 后新用户 balance=0，必须 POST /api/bank/deposit 充值才能取款。
// merchant.balance 仍是 0 直到第一笔成功 /payment 收款。

import { getDb, queryOne } from '../models/db.js';

/**
 * Initial balance credited to new customers on registration.
 *
 * v5 Phase 1 (1.5 开户改革)：改为 0。原 100 BC 教学赠送模式不符合
 * 真实 eCash 货币经济学（用户必须有法币入账才能换电子币）。新用户
 * 注册后 balance=0，前端 Dashboard 显示"充值"CTA 引导用户去 /bank。
 * 测试用 fundUser(id, amount) helper（调 bankService.deposit）充值。
 */
export const INITIAL_BALANCE_CUSTOMER = 0;

/**
 * Create a new user (INSERT into users).
 * Caller is responsible for hashing the password BEFORE calling this.
 *
 * Initial balance: customer → 100 (教学用), merchant → 0 (only /payment
 * credits merchant.balance — ISOLATION §一-2).
 *
 * @param {string} username pseudonym (unique)
 * @param {string} passwordHash bcrypt hash
 * @param {string} role 'customer' | 'merchant'
 * @returns {{id:number, username:string, role:string, balance:number, created_at:string}} created user (without password_hash)
 * @throws if username already exists (UNIQUE constraint)
 */
export function createUser(username, passwordHash, role) {
  const db = getDb();
  const initialBalance = role === 'customer' ? INITIAL_BALANCE_CUSTOMER : 0;
  const result = db.prepare(
    `INSERT INTO users (username, password_hash, role, balance) VALUES (?, ?, ?, ?)`
  ).run(username, passwordHash, role, initialBalance);
  return getUserById(result.lastInsertRowid);
}

/**
 * Get a user by username (used for login).
 * @param {string} username
 * @returns {{id, username, password_hash, role, balance, created_at}|undefined}
 */
export function getUserByUsername(username) {
  return queryOne(
    `SELECT id, username, password_hash, role, balance, created_at FROM users WHERE username = ?`,
    [username],
  );
}

/**
 * Get a user by id (used by auth middleware after JWT verification).
 * @param {number} id
 * @returns {{id, username, password_hash, role, balance, created_at}|undefined}
 */
export function getUserById(id) {
  return queryOne(
    `SELECT id, username, password_hash, role, balance, created_at FROM users WHERE id = ?`,
    [id],
  );
}

/**
 * Check if a username is already taken.
 * @param {string} username
 * @returns {boolean}
 */
export function usernameExists(username) {
  return !!getUserByUsername(username);
}
