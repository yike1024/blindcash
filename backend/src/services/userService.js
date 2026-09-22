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
// INITIAL_BALANCE_CUSTOMER (100, 教学用 — see professor's M5 design decision
// #2 "初始余额机制"). Without this, M5 /payment has no money to spend and
// M6 E2E is dead in the water. ISOLATION.md §一 explicitly notes this is the
// ONLY balance initialization path — merchant.balance stays 0 until the first
// successful /payment deposits to it.

import { getDb, queryOne } from '../models/db.js';

/**
 * Initial balance credited to new customers on registration (教学用).
 * Production eCash would require a fiat on-ramp; for the course demo we just
 * gift 100 so the withdrawal flow can run end-to-end without a top-up step.
 */
export const INITIAL_BALANCE_CUSTOMER = 100;

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
