// services/authService.js — M1: password hashing + JWT token management
//
// Auth model:
//   - Users register with a pseudonym + password + role (customer|merchant)
//   - Passwords are hashed with bcrypt (rounds=12) — NEVER stored plaintext
//   - On login, verify bcrypt hash, then issue a JWT (HS256, 24h expiry)
//   - The JWT carries { userId, username, role } — no password, no private keys
//   - auth middleware (middleware/auth.js) verifies the JWT; requireRole
//     middleware enforces RBAC on role-restricted routes
//
// Security notes:
//   - JWT secret MUST come from env in production; the fallback is dev-only.
//   - bcrypt rounds=12 (~300ms per hash) is a good balance for a teaching system.

import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

/** bcrypt cost factor — rounds=12 means 2^12 iterations (~300ms). */
const BCRYPT_ROUNDS = 12;

/** JWT secret — MUST be set via env in production. Fallback is dev-only. */
const JWT_SECRET = process.env.BC_JWT_SECRET || 'blindcash-dev-secret-change-me';

/** JWT token expiry — 24 hours (plenty for a course project). */
const JWT_EXPIRES_IN = '24h';

/**
 * Hash a plaintext password with bcrypt.
 * @param {string} plaintextPassword
 * @returns {Promise<string>} bcrypt hash
 */
export async function hashPassword(plaintextPassword) {
  if (typeof plaintextPassword !== 'string' || plaintextPassword.length === 0) {
    throw new Error('hashPassword: password must be a non-empty string');
  }
  return bcrypt.hash(plaintextPassword, BCRYPT_ROUNDS);
}

/**
 * Verify a plaintext password against a stored bcrypt hash.
 * @param {string} plaintextPassword
 * @param {string} storedHash
 * @returns {Promise<boolean>} true if match
 */
export async function verifyPassword(plaintextPassword, storedHash) {
  if (typeof plaintextPassword !== 'string' || typeof storedHash !== 'string') {
    return false;
  }
  return bcrypt.compare(plaintextPassword, storedHash);
}

/**
 * Issue a signed JWT for an authenticated user. Payload includes role so the
 * auth middleware can populate req.user.role for RBAC enforcement.
 * @param {{id:number, username:string, role:string}} user
 * @returns {string} JWT token
 */
export function generateToken(user) {
  if (!user || typeof user.id !== 'number' || !user.username || !user.role) {
    throw new Error('generateToken: user must have id (number), username (string), role (string)');
  }
  return jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN },
  );
}

/**
 * Verify a JWT and return the decoded payload (or null if invalid/expired).
 * @param {string} token
 * @returns {{userId:number, username:string, role:string, iat:number, exp:number}|null}
 */
export function verifyToken(token) {
  if (typeof token !== 'string' || token.length === 0) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null; // invalid signature, expired, malformed
  }
}
