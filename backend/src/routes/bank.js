// routes/bank.js — M3 + Phase 1: 银行公开接口 + 充值/退币
//
// v3 §5 M3 step 5 + §四-5 (风险评估):
//   GET  /api/bank/pubkey  → no auth, returns { public_key: hex }
//
// Phase 1 (v5 §三 1.2 + 1.3):
//   POST /api/bank/deposit → 需 JWT，自助充值（simulated fiat rail）
//   POST /api/bank/redeem  → 需 JWT，退币（复用 paymentService.processPayment）
//
// Why pubkey no auth: the bank's public key P is public knowledge — anyone
// (merchant, customer, observer) needs it to verify token signatures locally.
// Keeping it behind auth would defeat the "anyone can verify" property of
// blind sigs.
//
// CRITICAL: this route MUST NEVER expose private_key. Only public_key leaves
// the server. The defensive-test in tests/bankKeyService.test.js checks the
// response body for absence of any "private"-ish field.

import { Router } from 'express';
import { authenticateJWT } from '../middleware/auth.js';
import { requireRole } from '../middleware/requireRole.js';
import {
  getActivePublicKey, getActiveKeyVersion,
  getActivePublicKeyByDenom, getActiveKeyVersionByDenom,
} from '../services/bankKeyService.js';
import { DENOMINATIONS } from '../config/bank.js';
import { deposit, BankServiceError } from '../services/bankService.js';
import { processPayment, redeemSplit, PaymentError } from '../services/paymentService.js';
import { getDb } from '../models/db.js';
import { bytesToHex } from '../utils/hex.js';
import { logger } from '../utils/logger.js';

const router = Router();

/**
 * Map a thrown service error to an Express response. Service errors carry
 * their own {status, code}; anything else is a 500 (don't leak internals).
 */
function handleError(res, err) {
  if (err instanceof BankServiceError || err instanceof PaymentError) {
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  logger.error({ err: err.message, stack: err.stack }, 'bank route unexpected error');
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Internal server error' });
}

// GET /api/bank/pubkey
// Returns the bank's 33-byte compressed public key P = x·G as a 66-char hex
// string. No authentication required — P is public.
//
// Phase 1 (v5 §二 H2 N4)：用 getActivePublicKey() 而不是 getPublicKey()，
// 前向兼容 Phase 3 多密钥轮换（届时本函数查 status='active' 的密钥）。
router.get('/pubkey', async (_req, res) => {
  try {
    const publicKey = await getActivePublicKey();
    res.json({
      public_key: bytesToHex(publicKey),
      encoding: 'secp256k1-compressed',
      byte_length: 33,
      key_id: await getActiveKeyVersion(),
    });
  } catch (err) {
    return handleError(res, err);
  }
});

router.get('/pubkeys', async (_req, res) => {
  try {
    const denominations = {};
    for (const denom of DENOMINATIONS) {
      const pk = await getActivePublicKeyByDenom(denom);
      const kv = await getActiveKeyVersionByDenom(denom);
      denominations[denom] = {
        public_key: bytesToHex(pk),
        key_id: kv,
      };
    }
    res.json({
      denominations,
      encoding: 'secp256k1-compressed',
      byte_length: 33,
    });
  } catch (err) {
    return handleError(res, err);
  }
});

router.get('/reserve', authenticateJWT, requireRole('admin'), async (_req, res) => {
  try {
    const db = getDb();
    const reserve = await db.prepare(
      `SELECT total_issued, total_redeemed, reserve_balance, updated_at
       FROM bank_reserve WHERE id = 1`,
    ).get();
    const sumBalance = (await db.prepare(
      `SELECT COALESCE(SUM(balance), 0) AS s FROM users`,
    ).get()).s;
    const inFlight = (await db.prepare(
      `SELECT COALESCE(SUM(amount), 0) AS s
       FROM withdrawal_sessions
       WHERE status IN ('pending','submitted')`,
    ).get()).s;

    return res.json({
      total_issued: reserve.total_issued,
      total_redeemed: reserve.total_redeemed,
      reserve_balance: reserve.reserve_balance,
      in_flight: inFlight,
      sum_balance: sumBalance,
      updated_at: reserve.updated_at,
    });
  } catch (err) {
    logger.error({ err: err.message, stack: err.stack }, 'bank reserve route unexpected error');
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Internal server error' });
  }
});

router.post('/deposit', authenticateJWT, async (req, res) => {
  try {
    const { amount } = req.body || {};
    if (amount === undefined) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required field: amount',
      });
    }
    const result = await deposit({
      user_id: req.user.userId,
      amount,
      ip: req.ip,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

router.post('/redeem', authenticateJWT, async (req, res) => {
  try {
    const { serial, amount, R_prime, s_prime, key_id } = req.body || {};
    if (serial === undefined || amount === undefined
        || R_prime === undefined || s_prime === undefined) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required fields: serial, amount, R_prime, s_prime',
      });
    }
    const result = await processPayment({
      merchant_id: req.user.userId,
      serial,
      amount,
      R_prime,
      s_prime,
      key_id,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

router.post('/redeem-split', authenticateJWT, async (req, res) => {
  try {
    const { serial, amount, R_prime, s_prime, key_id, split_denomination } = req.body || {};
    if (serial === undefined || amount === undefined
        || R_prime === undefined || s_prime === undefined
        || split_denomination === undefined) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required fields: serial, amount, R_prime, s_prime, split_denomination',
      });
    }
    const result = await redeemSplit({
      user_id: req.user.userId,
      serial,
      amount,
      R_prime,
      s_prime,
      key_id,
      split_denomination,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

export default router;
