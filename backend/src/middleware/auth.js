// middleware/auth.js — M1: JWT authentication middleware
//
// Extracts the Bearer token from the Authorization header, verifies it via
// authService.verifyToken, and attaches the decoded user (incl. role) to
// req.user. Downstream role enforcement is handled by middleware/requireRole.js.

import { verifyToken } from '../services/authService.js';

/**
 * Express middleware: verify JWT from Authorization header.
 * On success: req.user = { userId, username, role } (from decoded token).
 * On failure: 401 Unauthorized.
 */
export function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Missing or malformed Authorization header (expected: Bearer <token>)',
    });
  }

  const token = authHeader.slice(7); // strip "Bearer "
  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'Invalid or expired token',
    });
  }

  req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
  next();
}

/**
 * Optional auth: if a valid Bearer token is present, attach req.user;
 * if absent or invalid, proceed without user context (public read-only access).
 */
export function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const decoded = verifyToken(token);
    if (decoded) {
      req.user = { userId: decoded.userId, username: decoded.username, role: decoded.role };
    }
  }
  next();
}
