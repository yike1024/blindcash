// middleware/requireRole.js — M1: role-based access control (RBAC)
//
// Enforces that the authenticated user holds a specific role before reaching
// a route handler. MUST run AFTER authenticateJWT (which sets req.user.role).
//
// Usage:
//   router.post('/withdraw/init', authenticateJWT, requireRole('customer'), handler);
//   router.post('/payment',      authenticateJWT, requireRole('merchant'), handler);

/**
 * Factory: returns a middleware that enforces the given role.
 * @param {string} role 'customer' | 'merchant'
 */
export function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Authentication required',
      });
    }
    if (req.user.role !== role) {
      return res.status(403).json({
        error: 'FORBIDDEN',
        message: `This action requires role '${role}'. You are '${req.user.role}'.`,
      });
    }
    next();
  };
}
