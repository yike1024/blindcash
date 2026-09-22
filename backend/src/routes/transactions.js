// routes/transactions.js — M7: 账本流水查询
//
// GET /api/transactions?limit=50  → 当前登录用户的交易流水（最新 limit 条）
//
// 返回用户的 withdraw / deposit / refund 流水，让取款去向可见。
// 仅需 authenticateJWT（任何角色都可看自己的流水）。

import { Router } from 'express';
import { authenticateJWT } from '../middleware/auth.js';
import { listTransactions } from '../services/transactionService.js';
import { bytesToHex } from '../utils/hex.js';

const router = Router();

// GET /api/transactions
router.get('/', authenticateJWT, (req, res) => {
  try {
    const limitRaw = Number(req.query.limit);
    const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? limitRaw : 50;
    const rows = listTransactions(req.user.userId, limit);
    // serial 是 Uint8Array，转成 hex 字符串便于前端展示与复制
    const out = rows.map((r) => ({
      id: r.id,
      kind: r.kind,
      amount: r.amount,
      counterparty: r.counterparty,
      serial_hex: r.serial ? bytesToHex(r.serial) : null,
      session_id: r.session_id,
      note: r.note,
      created_at: r.created_at,
    }));
    return res.json({ transactions: out });
  } catch (err) {
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

export default router;
