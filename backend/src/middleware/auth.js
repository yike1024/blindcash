// middleware/auth.js — M1: JWT authentication middleware
//
// Extracts the Bearer token from the Authorization header, verifies it via
// authService.verifyToken, and attaches the decoded user (incl. role) to
// req.user. Downstream role enforcement is handled by middleware/requireRole.js.
//
// Phase 2/3 验收 Q5 修正：本文件原有一个 requireAdmin() 中间件（Phase 3
// 新增），但 middleware/requireRole.js 已有通用 requireRole('admin')
// 工厂——两套 RBAC 实现并存会造成维护混乱。现已统一到 requireRole，
// admin.js 的 /audit + /rotate-key 改用 requireRole('admin')，本文件
// 只保留 authenticateJWT + optionalAuth。

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
