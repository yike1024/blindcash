// routes/withdrawal.js — M4/M7: 4-move withdrawal protocol endpoints (any logged-in user)
//
// v3 §2.3 + §5 M4:
//   POST /api/withdraw/init     ① { amount }                → { session_id, R[], amount, N }
//   POST /api/withdraw/submit   ③ { session_id, candidates } → { j }
//   POST /api/withdraw/reveal   ⑤ { session_id, revealed }    → { s_j }
//   POST /api/withdraw/cancel   ⑦ { session_id }             → { refunded, new_balance }
//
// M7: 角色解锁——任何已登录用户都能取款（原 customer-only 锁已去掉），
// 这样商户也能取款，形成"取款→转账→存款"的真·闭环。customer_id 列名
// 保留不改，语义变为"取款用户 id"。ISOLATION §一 的措辞相应更新为
// "任何 user.balance 由 /withdraw 取或 /payment 存增减"。
//
// Error mapping: WithdrawalError carries {status, code, message} → we forward
// those; anything else is a 500 (defensive — shouldn't happen under the
// protocol's own invariants, but surfaces DB/crypto failures loudly).

import { Router } from 'express';
import { authenticateJWT } from '../middleware/auth.js';
import {
  initWithdrawal,
  submitCandidates,
  revealAndSign,
  cancelWithdrawal,
  WithdrawalError,
} from '../services/withdrawalService.js';

const router = Router();

// M7: 任何已登录用户都可取款（角色锁已去掉）。
const withdrawGuard = [authenticateJWT];

/**
 * Map a thrown error to an Express response. WithdrawalError uses its
 * embedded status; anything else is a 500 (don't leak internals).
 */
function handleError(res, err) {
  if (err instanceof WithdrawalError) {
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
}

// ① POST /api/withdraw/init
router.post('/init', withdrawGuard, (req, res) => {
  try {
    const { amount } = req.body;
    if (amount === undefined) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: 'amount is required' });
    }
    const result = initWithdrawal({ customer_id: req.user.userId, amount });
    return res.status(201).json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

// ③ POST /api/withdraw/submit
router.post('/submit', withdrawGuard, (req, res) => {
  try {
    const { session_id, candidates } = req.body;
    if (!session_id) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: 'session_id is required' });
    }
    if (!Array.isArray(candidates)) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: 'candidates array is required' });
    }
    const result = submitCandidates({
      session_id,
      customer_id: req.user.userId,
      candidates,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

// ⑤ POST /api/withdraw/reveal
router.post('/reveal', withdrawGuard, (req, res) => {
  try {
    const { session_id, revealed } = req.body;
    if (!session_id) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: 'session_id is required' });
    }
    if (!Array.isArray(revealed)) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: 'revealed array is required' });
    }
    const result = revealAndSign({
      session_id,
      customer_id: req.user.userId,
      revealed,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

// ⑦ POST /api/withdraw/cancel
router.post('/cancel', withdrawGuard, (req, res) => {
  try {
    const { session_id } = req.body;
    if (!session_id) {
      return res.status(400).json({ error: 'VALIDATION_ERROR', message: 'session_id is required' });
    }
    const result = cancelWithdrawal({
      session_id,
      customer_id: req.user.userId,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

export default router;
