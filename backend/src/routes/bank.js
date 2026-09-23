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

const router = Router();

/**
 * Map a thrown service error to an Express response. Service errors carry
 * their own {status, code}; anything else is a 500 (don't leak internals).
 */
function handleError(res, err) {
  if (err instanceof BankServiceError || err instanceof PaymentError) {
    return res.status(err.status).json({ error: err.code, message: err.message });
  }
  return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
}

// GET /api/bank/pubkey
// Returns the bank's 33-byte compressed public key P = x·G as a 66-char hex
// string. No authentication required — P is public.
//
// Phase 1 (v5 §二 H2 N4)：用 getActivePublicKey() 而不是 getPublicKey()，
// 前向兼容 Phase 3 多密钥轮换（届时本函数查 status='active' 的密钥）。
router.get('/pubkey', (_req, res) => {
  const publicKey = getActivePublicKey();
  res.json({
    public_key: bytesToHex(publicKey),
    // encoding hint for clients: 33-byte secp256k1 compressed point
    encoding: 'secp256k1-compressed',
    byte_length: 33,
    // Phase 3 (v5 §三 3.2)：返回当前 active 密钥的真实 key_version，
    // 前端取款时把 key_id 写入 token v2 schema，支付/退币时拿它查公钥验签。
    // 密钥轮换后此字段会随 active 切换而变化。
    key_id: getActiveKeyVersion(),
  });
});

// GET /api/bank/pubkeys — Phase 6.1: 返回所有面额的 active 公钥映射
//
// 前端取款时按面额选择 denom，从本接口拿到对应 denom 的公钥 P 来
// 计算盲化承诺 R' = R + α·G + β·P。每个 denom 有独立的密钥对，
// 密钥轮换后对应 denom 的 key_id 会变化。
//
// No auth — public keys are public knowledge.
router.get('/pubkeys', (_req, res) => {
  const denominations = {};
  for (const denom of DENOMINATIONS) {
    const pk = getActivePublicKeyByDenom(denom);
    const kv = getActiveKeyVersionByDenom(denom);
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
});

// GET /api/bank/reserve — 管理员查发行总量与准备金状态
//
// Phase 1 验收项（审查补充）：让管理员可查看银行的货币发行/回收/准备金
// 状态，用于审计与教学演示。需 JWT + admin 角色。
//
// 返回的 in_flight 与 sum_balance 是实时计算的（非 bank_reserve 表里的
// 存储值），便于管理员核对不变量：
//   reserve_balance == sum_balance + (total_issued - total_redeemed) + in_flight
router.get('/reserve', authenticateJWT, requireRole('admin'), (_req, res) => {
  try {
    const db = getDb();
    const reserve = db.prepare(
      `SELECT total_issued, total_redeemed, reserve_balance, updated_at
       FROM bank_reserve WHERE id = 1`,
    ).get();
    const sumBalance = db.prepare(
      `SELECT COALESCE(SUM(balance), 0) AS s FROM users`,
    ).get().s;
    const inFlight = db.prepare(
      `SELECT COALESCE(SUM(amount), 0) AS s
       FROM withdrawal_sessions
       WHERE status IN ('pending','submitted')`,
    ).get().s;

    return res.json({
      total_issued: reserve.total_issued,
      total_redeemed: reserve.total_redeemed,
      reserve_balance: reserve.reserve_balance,
      in_flight: inFlight,
      sum_balance: sumBalance,
      updated_at: reserve.updated_at,
    });
  } catch (err) {
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

// POST /api/bank/deposit
// 自助充值（simulated fiat rail）：用户提交金额，系统模拟外部法币入账。
// 单次上限 MAX_DEPOSIT_PER_TX=1000，24h 滚动累计上限 MAX_DEPOSIT_PER_DAY=5000
// （bankService.js 实现）。
//
// 任何已登录用户都能充值——新用户 balance=0，必须先充值才能取款。
router.post('/deposit', authenticateJWT, (req, res) => {
  try {
    const { amount } = req.body || {};
    if (amount === undefined) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required field: amount',
      });
    }
    const result = deposit({
      user_id: req.user.userId,
      amount,
      ip: req.ip,
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

// POST /api/bank/redeem
// 退币：用户提交自己取款得到的 token，由系统兑付到自己账户。
//
// **M2 修正（v5 §三 1.3）**：参数名是 merchant_id 不是 payee_id——
// processPayment 的入参就是 merchant_id（见 [paymentService.js#L177]）。
// redeem 路由 = processPayment({merchant_id: req.user.id, ...token}) +
// note='退币'。语义上 redeem 与商户收款共享 spent_coins 表（同一 token
// 只能被消费一次）。
//
// **N4 修正（v5 §三 checklist #3）**：service 层用
// `getPublicKeyByVersion(key_id)` 而不是重载 `getPublicKey(key_id?)`——
// 这里把 token v2 的 key_id 透传给 processPayment，由它决定用哪个公钥
// 验签。Phase 1 单密钥时 key_id 始终是 1，Phase 3 多密钥轮换后才会
// 真正分流。
router.post('/redeem', authenticateJWT, (req, res) => {
  try {
    const { serial, amount, R_prime, s_prime, key_id } = req.body || {};
    if (serial === undefined || amount === undefined
        || R_prime === undefined || s_prime === undefined) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'required fields: serial, amount, R_prime, s_prime',
      });
    }
    const result = processPayment({
      merchant_id: req.user.userId,  // M2: 退币到自己
      serial,
      amount,
      R_prime,
      s_prime,
      key_id,  // N4: 透传给 service 层用 getPublicKeyByVersion
    });
    return res.json(result);
  } catch (err) {
    return handleError(res, err);
  }
});

// POST /api/bank/redeem-split — Phase 6.2: 部分取款 / 找零兑付（教学化）
//
// v6 §四 6.2 落地：用户持有大面额 token（如 50 BC），希望拆成更小面额
// 的零钱。由于 Chaum 协议下"找零"必须发行新 token（要走 4-move withdrawal），
// 本接口的简化语义是：把大额 token 全额退到账户 + 在 spent_coins 表按
// split_denomination 记账（教学化展示"等价于多少枚小币"）。用户随后可
// 另走 4-move 取款流程取 split_denomination 面额的新 token。
//
// body: { serial, amount, R_prime, s_prime, key_id?, split_denomination }
//   split_denomination ∈ {1, 5, 10, 50, 100}，必须能整除 amount
// returns: { deposited, new_balance, split_denomination, split_count, limitations }
//
// **隐私局限**（返回 limitations 数组，前端必须诚实展示）：
//   - 不是真正的 Chaum 找零（银行只全额退币，需另走取款流程）
//   - spent_coins 按 split_denomination 记账仅是教学展示
//   - 时间侧信道：大额兑付 + 后续小额取款可被关联（参考 Chaum 1985）
//
// 文献参考：
//   [1] Brands S. 1993. "Untraceable Off-Line Cash in Wallets with Observers".
//       Crypto'93. §3 — 商户侧找零协议的早期方案。
//   [2] Chaum D. 1985. "Security Without Identification". CACM 28(10).
//       §"Privacy" — 时间侧信道对匿名集的削弱。
router.post('/redeem-split', authenticateJWT, (req, res) => {
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
    const result = redeemSplit({
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
