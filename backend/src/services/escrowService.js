// services/escrowService.js — Phase 7: 在线托管与收款单防抢兑服务
//
// 依据《教授 A 的审查》与《教授 B 的审查》严格实现：
//   1. 两案合一：payment_escrows 承载收款单挑战（nonce）与两阶段托管状态机。
//   2. merchant_id 由服务端根据当前登录商户硬编码注入，禁止客户端指定。
//   3. 核心安全边界为服务端核验收款人身份，challenge 作为防重放一次性随机数。
//   4. 确认权（confirm）严格限制仅顾客（customer_id）拥有，商户无权自证。
//   5. Lock 阶段原子写入 spent_coins（防双花占位），老接口与新接口均无法抢兑。
//   6. 取消/退款（cancel/expired）采用法币退还顾客 balance，token 永久作废防信息泄漏。
//   7. 全流程在单连接事务中执行，并在事务结束时严谨断言 bank_reserve 不变量。

import { randomBytes, randomUUID } from 'node:crypto';
import { getDb, runImmediateTx } from '../models/db.js';
import { assertInvariant } from './bankReserveService.js';
import { formatGate, verifyTokenCrypto } from './paymentService.js';
import { logAction } from './auditService.js';
import { logger } from '../utils/logger.js';

export class EscrowError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'EscrowError';
    this.status = status;
    this.code = code;
  }
}

/**
 * 懒清理过期的收款单与锁定（由各接口触发，无需引入外部 cron）。
 * @param {object} db — 必须在同一个单连接事务中
 */
export async function lazyCleanupExpiredEscrows(db) {
  // 1. 将超时的 created 状态收款单标记为 expired
  await db.prepare(
    `UPDATE payment_escrows
     SET status = 'expired'
     WHERE status = 'created' AND expires_at < CURRENT_TIMESTAMP`
  ).run();

  // 2. 查询超时的 locked 状态托管单（顾客超期未确认收货，自动退款给顾客法币余额）
  const expiredLocked = await db.prepare(
    `SELECT id, customer_id, amount, serial
     FROM payment_escrows
     WHERE status = 'locked' AND expires_at < CURRENT_TIMESTAMP`
  ).all();

  for (const esc of expiredLocked) {
    // 退款给顾客法币账户
    if (esc.customer_id) {
      await db.prepare(
        `UPDATE users SET balance = balance + ? WHERE id = ?`
      ).run(esc.amount, esc.customer_id);

      await db.prepare(
        `INSERT INTO transactions (user_id, kind, amount, serial, note)
         VALUES (?, 'refund', ?, ?, ?)`
      ).run(esc.customer_id, esc.amount, esc.serial, `Escrow ${esc.id} timeout refund`);
    }

    // 托管单更新为 expired
    await db.prepare(
      `UPDATE payment_escrows SET status = 'expired' WHERE id = ?`
    ).run(esc.id);

    // token 永久作废：total_issued 减少（从发行总量中移除），total_redeemed 不变
    await db.prepare(
      `UPDATE bank_reserve SET total_issued = total_issued - ? WHERE id = 1`
    ).run(esc.amount);

    logger.info({ escrow_id: esc.id, amount: esc.amount }, 'escrow timeout auto-refunded to customer');
  }
}

/**
 * 商户创建收款单。
 * @param {{ merchant_id: number, amount: number, denomination?: number, ttlSeconds?: number }}
 */
export async function createEscrow({ merchant_id, amount, denomination = 1, ttlSeconds = 900 }) {
  if (!Number.isInteger(amount) || amount <= 0) {
    throw new EscrowError(400, 'INVALID_AMOUNT', 'amount must be a positive integer');
  }

  const escrowId = randomUUID();
  const challenge = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  await runImmediateTx(async (db) => {
    // 验证商户用户存在
    const merchant = await db.prepare(`SELECT id FROM users WHERE id = ?`).get(merchant_id);
    if (!merchant) {
      throw new EscrowError(404, 'MERCHANT_NOT_FOUND', 'Merchant user does not exist');
    }

    await db.prepare(
      `INSERT INTO payment_escrows (id, merchant_id, amount, denomination, challenge, expires_at, status)
       VALUES (?, ?, ?, ?, ?, ?, 'created')`
    ).run(escrowId, merchant_id, amount, denomination, challenge, expiresAt);

    await assertInvariant(db);
  });

  return {
    escrow_id: escrowId,
    merchant_id,
    amount,
    denomination,
    challenge,
    expires_at: expiresAt,
  };
}

/**
 * 顾客提交 token 并锁定到指定收款单。
 * 核心安全检查：
 *   - 校验 token 密码学正确性（格式与 Schnorr 签名）
 *   - 校验 challenge 匹配，且单据处于 created 状态、未过期
 *   - 将 token 写入 spent_coins（防双花）与 payment_escrows（状态 locked）
 *   - 此阶段商户余额不增加，断言扩展后的准备金不变量
 */
export async function lockToken({
  customer_id,
  escrow_id,
  challenge,
  serial,
  amount,
  R_prime,
  s_prime,
  key_id,
}) {
  // 1. 密码学与格式校验（在事务外做重 CPU 运算）
  const { serialBytes, RPrimeBytes, sPrimeBytes } = formatGate({
    serial,
    amount,
    R_prime,
    s_prime,
  });

  const { tokenHash, publicKey, effectiveKeyVersion } = await verifyTokenCrypto({
    serialBytes,
    amount,
    RPrimeBytes,
    sPrimeBytes,
    key_id,
  });

  // 2. 事务内执行状态机流转与防双花
  return await runImmediateTx(async (db) => {
    await lazyCleanupExpiredEscrows(db);

    const escrow = await db.prepare(
      `SELECT * FROM payment_escrows WHERE id = ?`
    ).get(escrow_id);

    if (!escrow) {
      throw new EscrowError(404, 'ESCROW_NOT_FOUND', 'Payment escrow not found');
    }

    if (escrow.status !== 'created') {
      throw new EscrowError(400, 'INVALID_STATUS', `Cannot lock escrow in status '${escrow.status}'`);
    }

    if (new Date(escrow.expires_at) < new Date()) {
      await db.prepare(`UPDATE payment_escrows SET status = 'expired' WHERE id = ?`).run(escrow_id);
      throw new EscrowError(400, 'ESCROW_EXPIRED', 'Payment escrow has expired');
    }

    if (escrow.challenge !== challenge) {
      throw new EscrowError(400, 'CHALLENGE_MISMATCH', 'Invalid escrow challenge nonce');
    }

    if (escrow.amount !== amount) {
      throw new EscrowError(400, 'AMOUNT_MISMATCH', `Escrow requires ${escrow.amount}, got ${amount}`);
    }

    // 检查 spent_coins 是否已存在（拦截双花）
    const existing = await db.prepare(
      `SELECT serial FROM spent_coins WHERE serial = ? OR token_hash = ?`
    ).get(Buffer.from(serialBytes), Buffer.from(tokenHash));

    if (existing) {
      throw new EscrowError(409, 'DOUBLE_SPEND', 'Token already spent or locked');
    }

    // 将 serial 占位插入 spent_coins（防止跨接口绕道抢兑，deposited_to 绑定收款商户）
    await db.prepare(
      `INSERT INTO spent_coins (serial, amount, deposited_to, token_hash, key_version, denomination)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(
      Buffer.from(serialBytes),
      amount,
      escrow.merchant_id,
      Buffer.from(tokenHash),
      effectiveKeyVersion,
      escrow.denomination ?? 1,
    );

    // 更新 payment_escrows 为 locked
    await db.prepare(
      `UPDATE payment_escrows
       SET customer_id = ?,
           serial = ?,
           token_hash = ?,
           status = 'locked',
           locked_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).run(
      customer_id,
      Buffer.from(serialBytes),
      Buffer.from(tokenHash),
      escrow_id,
    );

    // 断言准备金不变量（locked 状态资金计入 inFlightEscrows，等式守恒）
    await assertInvariant(db);

    await logAction({
      actor_id: customer_id,
      action: 'escrow_locked',
      target: escrow_id,
      amount,
      meta: JSON.stringify({ merchant_id: escrow.merchant_id }),
    });

    return {
      escrow_id,
      merchant_id: escrow.merchant_id,
      customer_id,
      amount,
      status: 'locked',
    };
  });
}

/**
 * 顾客确认交付结算（Confirm）。
 * 严格限制：只有 customer_id 本人才能确认；商户无法自证 confirm。
 */
export async function confirmEscrow({ customer_id, escrow_id }) {
  return await runImmediateTx(async (db) => {
    await lazyCleanupExpiredEscrows(db);

    const escrow = await db.prepare(
      `SELECT * FROM payment_escrows WHERE id = ?`
    ).get(escrow_id);

    if (!escrow) {
      throw new EscrowError(404, 'ESCROW_NOT_FOUND', 'Payment escrow not found');
    }

    if (escrow.status !== 'locked') {
      throw new EscrowError(400, 'INVALID_STATUS', `Cannot confirm escrow in status '${escrow.status}'`);
    }

    // 核心安全边界：必须是锁定该单的顾客本人
    if (escrow.customer_id !== customer_id) {
      throw new EscrowError(403, 'FORBIDDEN', 'Only the customer who locked this payment can confirm');
    }

    // 1. 将商户余额增加
    await db.prepare(
      `UPDATE users SET balance = balance + ? WHERE id = ?`
    ).run(escrow.amount, escrow.merchant_id);

    // 2. 准备金 total_redeemed 增加（token 正式被核销结算，退出流通）
    await db.prepare(
      `UPDATE bank_reserve SET total_redeemed = total_redeemed + ? WHERE id = 1`
    ).run(escrow.amount);

    // 3. 记录商户入账流水
    await db.prepare(
      `INSERT INTO transactions (user_id, kind, amount, serial, note)
       VALUES (?, 'deposit', ?, ?, ?)`
    ).run(escrow.merchant_id, escrow.amount, escrow.serial, `Escrow ${escrow_id} settled`);

    // 4. 更新托管状态为 committed
    await db.prepare(
      `UPDATE payment_escrows
       SET status = 'committed', committed_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).run(escrow_id);

    // 5. 断言准备金不变量（locked 减少，users.balance 与 total_redeemed 增加，严格守恒）
    await assertInvariant(db);

    // 查询更新后的商户余额，返回给前端用于即时刷新
    const merchant = await db.prepare(
      `SELECT balance FROM users WHERE id = ?`
    ).get(escrow.merchant_id);

    await logAction({
      actor_id: customer_id,
      action: 'escrow_committed',
      target: escrow_id,
      amount: escrow.amount,
      meta: JSON.stringify({ merchant_id: escrow.merchant_id }),
    });

    return {
      escrow_id,
      merchant_id: escrow.merchant_id,
      customer_id,
      amount: escrow.amount,
      status: 'committed',
      merchant_balance: merchant?.balance,
    };
  });
}

/**
 * 撤销托管退款（Cancel）。
 * 规则：
 *   - 若处于 created：商户可随时撤销。
 *   - 若处于 locked：
 *       - 商户可主动退款给顾客（如缺货）；
 *       - 顾客在超时后可主动申请退款；
 *       - 退款以法币直接返还到顾客 users.balance，原 token 永久废弃，消除商户抵赖空间。
 */
export async function cancelEscrow({ user_id, escrow_id }) {
  return await runImmediateTx(async (db) => {
    await lazyCleanupExpiredEscrows(db);

    const escrow = await db.prepare(
      `SELECT * FROM payment_escrows WHERE id = ?`
    ).get(escrow_id);

    if (!escrow) {
      throw new EscrowError(404, 'ESCROW_NOT_FOUND', 'Payment escrow not found');
    }

    if (escrow.status === 'committed' || escrow.status === 'cancelled' || escrow.status === 'expired') {
      throw new EscrowError(400, 'INVALID_STATUS', `Cannot cancel escrow in status '${escrow.status}'`);
    }

    if (escrow.status === 'created') {
      if (escrow.merchant_id !== user_id) {
        throw new EscrowError(403, 'FORBIDDEN', 'Only merchant can cancel an open invoice');
      }
      await db.prepare(
        `UPDATE payment_escrows SET status = 'cancelled', cancelled_at = CURRENT_TIMESTAMP WHERE id = ?`
      ).run(escrow_id);

      await assertInvariant(db);
      return { escrow_id, status: 'cancelled' };
    }

    // locked 状态下：商户可主动退还，或顾客在超时后可退款
    const isMerchant = escrow.merchant_id === user_id;
    const isCustomer = escrow.customer_id === user_id;
    const isExpired = new Date(escrow.expires_at) < new Date();

    if (!isMerchant && !(isCustomer && isExpired)) {
      throw new EscrowError(403, 'FORBIDDEN', 'Merchant can refund anytime; customer can only refund after expiration');
    }

    // 执行退款给顾客法币账户
    if (escrow.customer_id) {
      await db.prepare(
        `UPDATE users SET balance = balance + ? WHERE id = ?`
      ).run(escrow.amount, escrow.customer_id);

      await db.prepare(
        `INSERT INTO transactions (user_id, kind, amount, serial, note)
         VALUES (?, 'refund', ?, ?, ?)`
      ).run(escrow.customer_id, escrow.amount, escrow.serial, `Escrow ${escrow_id} refund`);
    }

    // token 永久作废：total_issued 减少（从发行总量中移除），total_redeemed 不变
    await db.prepare(
      `UPDATE bank_reserve SET total_issued = total_issued - ? WHERE id = 1`
    ).run(escrow.amount);

    await db.prepare(
      `UPDATE payment_escrows SET status = 'cancelled', cancelled_at = CURRENT_TIMESTAMP WHERE id = ?`
    ).run(escrow_id);

    await assertInvariant(db);

    // 查询退款后的顾客余额，返回给前端用于即时刷新
    const customer = await db.prepare(
      `SELECT balance FROM users WHERE id = ?`
    ).get(escrow.customer_id);

    await logAction({
      actor_id: user_id,
      action: 'escrow_cancelled',
      target: escrow_id,
      amount: escrow.amount,
      meta: JSON.stringify({ refunded_to: escrow.customer_id }),
    });

    return { escrow_id, status: 'cancelled', refunded_to: escrow.customer_id, amount: escrow.amount, refund_balance: customer?.balance };
  });
}

/**
 * 查询指定 escrow 详情（附带懒清理）。
 * 若传入 requesting_user_id，则校验权限：仅允许该单据的商户或顾客本人查询。
 */
export async function getEscrowDetails(escrow_id, requesting_user_id = null) {
  const db = getDb();
  await runImmediateTx(async (tx) => {
    await lazyCleanupExpiredEscrows(tx);
  });
  const row = await db.prepare(`SELECT * FROM payment_escrows WHERE id = ?`).get(escrow_id);
  if (!row) return null;

  if (requesting_user_id) {
    const isParty = row.merchant_id === requesting_user_id || row.customer_id === requesting_user_id;
    if (!isParty) {
      throw new EscrowError(403, 'FORBIDDEN', 'Access denied to this escrow record');
    }
  }

  return row;
}

/**
 * 列出当前用户的在途与历史托管单。
 * JOIN users 表获取商户与顾客的用户名，供前端展示。
 */
export async function listUserEscrows(user_id) {
  const db = getDb();
  return await db.prepare(
    `SELECT pe.*,
            mu.username AS merchant_name,
            cu.username AS customer_name
     FROM payment_escrows pe
     LEFT JOIN users mu ON mu.id = pe.merchant_id
     LEFT JOIN users cu ON cu.id = pe.customer_id
     WHERE pe.merchant_id = ? OR pe.customer_id = ?
     ORDER BY pe.created_at DESC`
  ).all(user_id, user_id);
}
