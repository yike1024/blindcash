// services/userService.js — M1: user (pseudonym) CRUD with role
//
// users table columns: id, username (UNIQUE), password_hash, role, balance, created_at
// (M1: role + balance added on top of the cryptobank userService pattern)
//
// We store only the bcrypt hash of the password. The plaintext never touches
// the database. Role is immutable after registration (enforced by API: no
// update-role endpoint).

import { getDb, queryOne } from '../models/db.js';

/**
 * Create a new user (INSERT into users).
 * Caller is responsible for hashing the password BEFORE calling this.
 *
 * @param {string} username pseudonym (unique)
 * @param {string} passwordHash bcrypt hash
 * @param {string} role 'customer' | 'merchant'
 * @returns {{id:number, username:string, role:string, balance:number, created_at:string}} created user (without password_hash)
 * @throws if username already exists (UNIQUE constraint)
 */
export function createUser(username, passwordHash, role) {
  const db = getDb();
  const result = db.prepare(
    `INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`
  ).run(username, passwordHash, role);
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
