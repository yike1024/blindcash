// routes/auth.js — M1: user registration + login routes (with role)
//
// POST /api/auth/register  { username, password, role } → { user, token }
// POST /api/auth/login     { username, password }        → { user, token }
//
// The response includes a JWT token so the front-end can immediately call
// protected routes after register/login without a second round-trip.
// The token payload carries `role` for RBAC enforcement downstream.

import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import { hashPassword, verifyPassword, generateToken } from '../services/authService.js';
import { createUser, getUserByUsername, usernameExists } from '../services/userService.js';

const router = Router();

const VALID_ROLES = ['customer', 'merchant'];

// POST /api/auth/register
router.post(
  '/register',
  [
    body('username')
      .isString()
      .isLength({ min: 3, max: 32 })
      .withMessage('username must be 3-32 chars')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('username may only contain letters, digits, - and _'),
    body('password')
      .isString()
      .isLength({ min: 8, max: 128 })
      .withMessage('密码长度至少 8 位')
      .matches(/[a-zA-Z]/)
      .withMessage('密码必须包含字母')
      .matches(/[0-9]/)
      .withMessage('密码必须包含数字')
      .matches(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`!]/)
      .withMessage('密码必须包含特殊字符'),
    body('role')
      .isString()
      .isIn(VALID_ROLES)
      .withMessage('role must be one of: customer, merchant'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', details: errors.array() });
    }

    const { username, password, role } = req.body;

    // Username uniqueness check (also enforced by DB UNIQUE constraint as a safety net)
    if (usernameExists(username)) {
      return res.status(409).json({
        error: 'USERNAME_TAKEN',
        message: `username '${username}' is already taken`,
      });
    }

    try {
      // Hash the password BEFORE persisting (bcrypt rounds=12)
      const passwordHash = await hashPassword(password);
      const user = createUser(username, passwordHash, role);

      // Issue JWT immediately so the front-end is authenticated
      const token = generateToken(user);

      // Phase 1 (v5 §三 1.5 开户改革)：新用户 balance=0，前端 Dashboard
      // 显示"请先充值"CTA 引导用户去 /bank。这里在 register 响应里也带
      // 一个 hint，让客户端无需检查 balance 也能展示充值引导。
      return res.status(201).json({
        user: { id: user.id, username: user.username, role: user.role, balance: user.balance },
        token,
        hint: user.role === 'customer' && user.balance === 0
          ? 'account opened with balance=0; please deposit at /api/bank/deposit before withdrawing'
          : null,
      });
    } catch (e) {
      // Catch any DB-level UNIQUE violation (race condition)
      if (e.message && e.message.includes('UNIQUE')) {
        return res.status(409).json({ error: 'USERNAME_TAKEN', message: `username '${username}' is already taken` });
      }
      return res.status(500).json({ error: 'INTERNAL_ERROR', message: e.message });
    }
  },
);

// POST /api/auth/login
router.post(
  '/login',
  [
    body('username').isString().notEmpty().withMessage('username is required'),
    body('password').isString().notEmpty().withMessage('password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', details: errors.array() });
    }

    const { username, password } = req.body;
    const user = getUserByUsername(username);

    if (!user) {
      // Generic message to avoid username enumeration (security best practice)
      return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'invalid username or password' });
    }

    const passwordOk = await verifyPassword(password, user.password_hash);
    if (!passwordOk) {
      return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'invalid username or password' });
    }

    const token = generateToken(user);
    return res.json({
      user: { id: user.id, username: user.username, role: user.role, balance: user.balance },
      token,
    });
  },
);

export default router;
