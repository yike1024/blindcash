// routes/withdrawal.js — M4: 4-move withdrawal protocol endpoints (customer-only)
//
// v3 §2.3 + §5 M4:
//   POST /api/withdraw/init     ① { amount }                → { session_id, R[], amount, N }
//   POST /api/withdraw/submit   ③ { session_id, candidates } → { j }
//   POST /api/withdraw/reveal   ⑤ { session_id, revealed }    → { s_j }
//   POST /api/withdraw/cancel   ⑦ { session_id }             → { refunded, new_balance }
//
// All four require authenticateJWT + requireRole('customer') — ISOLATION §一
// (customer.balance only moves via /withdraw/*). Merchant calls hit 403 before
// reaching the service layer.
//
// Error mapping: WithdrawalError carries {status, code, message} → we forward
// those; anything else is a 500 (defensive — shouldn't happen under the
// protocol's own invariants, but surfaces DB/crypto failures loudly).

import { Router } from 'express';
import { authenticateJWT } from '../middleware/auth.js';
import { requireRole } from '../middleware/requireRole.js';
import {
  initWithdrawal,
  submitCandidates,
  revealAndSign,
  cancelWithdrawal,
  WithdrawalError,
} from '../services/withdrawalService.js';

const router = Router();

// All /withdraw/* routes are customer-only.
const customerGuard = [authenticateJWT, requireRole('customer')];

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
router.post('/init', customerGuard, (req, res) => {
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
router.post('/submit', customerGuard, (req, res) => {
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
router.post('/reveal', customerGuard, (req, res) => {
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
router.post('/cancel', customerGuard, (req, res) => {
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
