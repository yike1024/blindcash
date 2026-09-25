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
import {
  createEscrow,
  lockToken,
  confirmEscrow,
  cancelEscrow,
  getEscrowDetails,
  listUserEscrows,
  EscrowError,
} from '../services/escrowService.js';
import { logger } from '../utils/logger.js';

const router = Router();

// 任何已登录用户都可参与支付/收款。
const depositGuard = [authenticateJWT];

/**
 * Map a thrown error to an Express response.
 */
function handleError(res, err) {
  if (err instanceof PaymentError || err instanceof EscrowError) {
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  logger.error({ err: err.message, stack: err.stack }, 'payment route unexpected error');
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: 'Internal server error' });
}

// ─────────────────────────────────────────────────────────────
// 阶段 7: 在线托管与收款单接口 (Escrow / Invoice API)
// ─────────────────────────────────────────────────────────────

/**
 * POST /api/payment/escrow
 * 商户创建收款单。
 * merchant_id 由服务端从 req.user.userId 注入，禁止由客户端随意伪造。
 */
router.post('/escrow', depositGuard, async (req, res) => {
  try {
    const { amount, denomination, ttl_seconds } = req.body || {};
    if (!amount) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required field: amount',
      });
    }

    const escrow = await createEscrow({
      merchant_id: req.user.userId,
      amount,
      denomination,
      ttlSeconds: ttl_seconds,
    });
    return res.status(201).json(escrow);
  } catch (err) {
    return handleError(res, err);
  }
});

/**
 * GET /api/payment/escrows
 * 查询当前用户的在途与历史收款/托管单。
 */
router.get('/escrows', depositGuard, async (req, res) => {
  try {
    const rows = await listUserEscrows(req.user.userId);
    return res.json({ escrows: rows });
  } catch (err) {
    return handleError(res, err);
  }
});

/**
 * GET /api/payment/escrow/:id
 * 获取指定收款单状态（附带超时懒清理与权限校验）。
 */
router.get('/escrow/:id', depositGuard, async (req, res) => {
  try {
    const escrow = await getEscrowDetails(req.params.id, req.user?.userId);
    if (!escrow) {
      return res.status(404).json({ error: 'NOT_FOUND', message: 'Escrow not found' });
    }
    return res.json(escrow);
  } catch (err) {
    return handleError(res, err);
  }
});

/**
 * POST /api/payment/lock
 * 顾客提交 token 锁定到指定收款单。
 * 核心：验签 + challenge 匹配 + 双花占位 + 资金锁定。
 */
router.post('/lock', depositGuard, async (req, res) => {
  try {
    const { escrow_id, challenge, serial, amount, R_prime, s_prime, key_id } = req.body || {};
    if (!escrow_id || !challenge || !serial || amount === undefined || !R_prime || !s_prime) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required fields: escrow_id, challenge, serial, amount, R_prime, s_prime',
      });
    }

    const result = await lockToken({
      customer_id: req.user.userId,
      escrow_id,
      challenge,
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

/**
 * POST /api/payment/confirm
 * 顾客确认交付结算（Confirm）。
 * 严格限制：仅锁定该单的 customer_id 可调用。
 */
router.post('/confirm', depositGuard, async (req, res) => {
  try {
    const { escrow_id } = req.body || {};
    if (!escrow_id) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required field: escrow_id',
      });
    }

    const result = await confirmEscrow({
      customer_id: req.user.userId,
      escrow_id,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

/**
 * POST /api/payment/cancel
 * 撤销/退款托管单。
 * 商户可主动取消/退款；顾客超期可申请退款。
 */
router.post('/cancel', depositGuard, async (req, res) => {
  try {
    const { escrow_id } = req.body || {};
    if (!escrow_id) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required field: escrow_id',
      });
    }

    const result = await cancelEscrow({
      user_id: req.user.userId,
      escrow_id,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────
// 基础直接兑付接口（向后兼容测试与直接存款模式）
// ─────────────────────────────────────────────────────────────

// POST /api/payment
router.post('/', depositGuard, async (req, res) => {
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

export default router;
