// services/privacyService.js — Phase 6.3: 匿名集分析
//
// v6 §四 6.3 落地：
//   对用户持有的每个 token，计算其在银行视角下的匿名集大小。
//   匿名集 = spent_coins 表中相同 (denomination, key_version) 的 token 数量。
//
// **隐私局限（诚实文档化）**：
//   1. 匿名集只统计已花费的 token（在 spent_coins 表中）。未花费的 token
//      在客户端 IndexedDB 中，银行不知道。所以这是一个下界——银行视角
//      下至少这么多 token 与你的不可区分。
//   2. 银行理论上还能用时间侧信道（取款时间 vs 支付时间）缩小集合。
//      Chaum 原始协议不防时间侧信道，本系统也不防。
//   3. 如果同一 (denom, key_version) 只有 1 枚 token 被花费，匿名集=1，
//      意味着银行可以确定地关联该 token 的取款和支付。
//
// 服务端不知道用户持有哪些 token（钱包在客户端 IndexedDB），所以前端
// 把 token 列表（只含 key_id）发到 POST /api/privacy/report，服务端用
// key_id 反查 denom，再统计 spent_coins。

import { queryOne } from '../models/db.js';
import { getDenominationByVersion } from './bankKeyService.js';

/**
 * Compute anonymity set report for a list of tokens.
 * @returns {Promise<{report: Array, limitations: string[]}>}
 */
export async function computeAnonymityReport(tokens) {
  if (!Array.isArray(tokens)) {
    return { report: [], limitations: PRIVACY_LIMITATIONS };
  }

  const userHoldings = new Map();
  const seenPairs = new Set();

  for (const token of tokens) {
    if (token?.key_id == null) continue;
    let denom;
    try {
      denom = await getDenominationByVersion(token.key_id);
    } catch {
      continue;
    }
    const pairKey = `${denom}:${token.key_id}`;
    userHoldings.set(pairKey, (userHoldings.get(pairKey) ?? 0) + 1);
  }

  const report = [];
  for (const [pairKey, userCount] of userHoldings) {
    const [denomStr, kvStr] = pairKey.split(':');
    const denom = parseInt(denomStr, 10);
    const keyVersion = parseInt(kvStr, 10);

    const row = await queryOne(
      `SELECT COUNT(*) AS cnt FROM spent_coins WHERE key_version = ?`,
      [keyVersion],
    );

    report.push({
      denomination: denom,
      key_version: keyVersion,
      anonymity_set_size: row?.cnt ?? 0,
      your_tokens: userCount,
    });
  }

  report.sort((a, b) => a.denomination - b.denomination);

  return { report, limitations: PRIVACY_LIMITATIONS };
}

const PRIVACY_LIMITATIONS = [
  '匿名集只统计已花费的 token（spent_coins 表）。未花费的 token 在客户端钱包中，银行不可见，故这是下界。',
  '银行理论上能用时间侧信道（取款时间 vs 支付时间）缩小集合。Chaum 原始协议不防时间侧信道，本系统也不防。',
  '如果匿名集=1，银行可确定地关联该 token 的取款与支付身份。',
];
