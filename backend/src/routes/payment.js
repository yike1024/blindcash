// routes/payment.js — M5: payment endpoint (merchant-only)
//
// v3 §四-4 + professor's M5 design decision #1:
//   POST /api/payment  { serial, amount, R_prime, s_prime }
//     → 200 { deposited, new_balance }
//
// Auth: authenticateJWT + requireRole('merchant') — ISOLATION §一-2 (merchant.balance
// is ONLY mutated by this route). Customer calls hit 403 before reaching the
// service layer (so a customer can never credit their own balance by replaying
// a withdrawn token).
//
// Token transmission uses STRUCTURED FIELDS (not a JSON blob) so the format
// gate in processPayment can 400 each malformed field individually.
//
// Error mapping: PaymentError → its {status, code, message}; anything else → 500.

import { Router } from 'express';
import { authenticateJWT } from '../middleware/auth.js';
import { requireRole } from '../middleware/requireRole.js';
import { processPayment, PaymentError } from '../services/paymentService.js';

const router = Router();

// All /payment routes are merchant-only.
const merchantGuard = [authenticateJWT, requireRole('merchant')];

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
router.post('/', merchantGuard, (req, res) => {
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
