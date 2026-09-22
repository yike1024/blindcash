// routes/payment.js — M5/M7: payment endpoint (any logged-in user)
//
// v3 §四-4 + professor's M5 design decision #1:
//   POST /api/payment  { serial, amount, R_prime, s_prime }
//     → 200 { deposited, new_balance }
//
// M7: 角色解锁——Chaum 式真·转账闭环。任何已登录用户都能存 token
// （原 merchant-only 锁已去掉），这样顾客取款后能把 token 转给另一个
// 顾客/商户存款，token 即可转让货币。服务器仍独立做 verifySig + 双花
// 检测，角色锁不是安全边界（crypto + spent_coins UNIQUE 才是）。
//
// Token transmission uses STRUCTURED FIELDS (not a JSON blob) so the format
// gate in processPayment can 400 each malformed field individually.
//
// Error mapping: PaymentError → its {status, code, message}; anything else → 500.

import { Router } from 'express';
import { authenticateJWT } from '../middleware/auth.js';
import { processPayment, PaymentError } from '../services/paymentService.js';

const router = Router();

// M7: 任何已登录用户都可存款（角色锁已去掉）。
const depositGuard = [authenticateJWT];

/**
 * Map a thrown error to an Express response. PaymentError uses its embedded
 * status; anything else is a 500 (don't leak internals).
 */
function handleError(res, err) {
  if (err instanceof PaymentError) {
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
}

// POST /api/payment
router.post('/', depositGuard, (req, res) => {
  try {
    const { serial, amount, R_prime, s_prime } = req.body || {};
    // Field presence check — service layer does the deeper format gate.
    if (serial === undefined || amount === undefined
        || R_prime === undefined || s_prime === undefined) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required fields: serial, amount, R_prime, s_prime',
      });
    }
    const result = processPayment({
      merchant_id: req.user.userId,
      serial,
      amount,
      R_prime,
      s_prime,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

export default router;
