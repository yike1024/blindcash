// routes/admin.js — Phase 3: 管理员审计日志 + 密钥轮换接口
//
// v5 §三 3.3 落地：
//   GET  /api/admin/audit?page=&pageSize=&action= — 管理员分页查审计日志
//   POST /api/admin/rotate-key                      — 管理员触发密钥轮换
//
// requireAdmin 中间件保证只有 admin 角色能访问（403 for others）。

import { Router } from 'express';
import { authenticateJWT, requireAdmin } from '../middleware/auth.js';
import { queryAuditLog } from '../services/auditService.js';
import { rotateKey } from '../services/bankKeyService.js';

const router = Router();

// GET /api/admin/audit — 分页查询审计日志
// Query params:
//   page     — 1-based page number (default 1)
//   pageSize — entries per page (default 20, max 100)
//   action   — filter by action type (optional, e.g. 'deposit', 'key_rotate')
router.get('/audit', authenticateJWT, requireAdmin, (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize, 10) || 20));
    const action = req.query.action || undefined;

    const result = queryAuditLog({ page, pageSize, action });
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

// POST /api/admin/rotate-key — 触发密钥轮换
// 旧密钥标记 retired + retired_until=now+90d，生成新 active 密钥。
// 返回新旧 key_version。
router.post('/rotate-key', authenticateJWT, requireAdmin, (req, res) => {
  try {
    const result = rotateKey(req.user.userId);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

export default router;
