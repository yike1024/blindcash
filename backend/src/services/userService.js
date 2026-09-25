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
 */
export const INITIAL_BALANCE_CUSTOMER = 0;

/**
 * Create a new user (INSERT into users).
 * @returns {Promise<{id:number, username:string, role:string, balance:number, created_at:string}>}
 */
export async function createUser(username, passwordHash, role) {
  const db = getDb();
  const initialBalance = role === 'customer' ? INITIAL_BALANCE_CUSTOMER : 0;
  const result = await db.prepare(
    `INSERT INTO users (username, password_hash, role, balance) VALUES (?, ?, ?, ?)`
  ).run(username, passwordHash, role, initialBalance);
  return getUserById(result.lastInsertRowid);
}

/**
 * Get a user by username (used for login).
 * @returns {Promise<{...}|undefined>}
 */
export async function getUserByUsername(username) {
  return queryOne(
    `SELECT id, username, password_hash, role, balance, created_at FROM users WHERE username = ?`,
    [username],
  );
}

/**
 * Get a user by id.
 * @returns {Promise<{...}|undefined>}
 */
export async function getUserById(id) {
  return queryOne(
    `SELECT id, username, password_hash, role, balance, created_at FROM users WHERE id = ?`,
    [id],
  );
}

/**
 * Check if a username is already taken.
 * @returns {Promise<boolean>}
 */
export async function usernameExists(username) {
  return !!(await getUserByUsername(username));
}
