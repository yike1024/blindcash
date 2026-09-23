// middleware/rateLimit.js — Phase 4 (v5 §三 4): 三级速率限制
//
// v5 §三 4 落地：express-rate-limit v7+，三个限流器分级：
//   globalLimiter — 100 req/min/IP，全路由覆盖（含未认证的 /api/health、
//                   /api/bank/pubkey）。防总体洪水攻击。
//   authLimiter   — 5 req/min/IP，挂在 /api/auth/register + /api/auth/login。
//                   防密码爆破 / 注册刷量。
//   txLimiter      — 10 req/min/user，挂在 /api/withdraw + /api/payment。
//                   防取款/支付接口被脚本刷。
//
// ⚠️ Phase 2/3 验收 Q（最高优先级）："限流会打死自己的 168 个测试"——
//   skip: () => isTest 让 NODE_ENV=test 时限流器变 no-op。Vitest 运行时
//   vitest 自动设 NODE_ENV=test，主测试套件全绿。但**保留专项限流测试**
//   （rateLimit.test.js）手动构造 limiter 实例，不走 skip 路径，验证 429
//   + Retry-After header——否则限流在主套件里隐形等于没验证。
//
// ⚠️ Phase 2/3 验收 Q（keyGenerator 陷阱）：
//   txLimiter 的 keyGenerator 用 `req.user?.userId`——但限流中间件跑在
//   `authenticateJWT` 之前时 req.user 是 undefined。express-rate-limit v7+
//   对自定义 keyGenerator 返回 IP 时有 ipv6Subnet 校验警告——混合返回值
//   （userId 字符串 / IP 字符串）会触发 ValidationError。
//   解法：用库自带的 ipKeyGenerator 做回退（它正确处理 IPv6 子网），
//   不自己拼 req.ip。已认证用 userId key（更稳定，IP 共享会误伤），
//   未认证回退到 ipKeyGenerator。
//
// 文献参考：
//   [1] OWASP ASVS L1 v4.0.31 §11.1.1 — "verify that rate limiting is in place
//       for authentication, session management, and other sensitive flows"。
//   [2] NIST SP 800-63Brev2 §5.2.2 — "throttle authentication attempts to
//       mitigate brute force"，authLimiter 的 5 req/min 即此要求落地。

import rateLimit, { ipKeyGenerator } from 'express-rate-limit';

const isTest = process.env.NODE_ENV === 'test' || !!process.env.VITEST;

// 公共 skip：测试环境全 no-op
const skip = () => isTest;

// 已认证用户的 key 生成器——用 userId 比 IP 稳定（IP 共享会误伤，
// 移动网络切换 IP 会绕过限流）。未认证回退到库自带的 ipKeyGenerator，
// 避免自己拼 req.ip 触发 v7+ 的 ipv6Subnet 警告。
function userKeyGenerator(req) {
  if (req.user?.userId != null) {
    return `user:${req.user.userId}`;
  }
  return ipKeyGenerator(req);
}

/**
 * 全局限流器：100 req/min/IP。挂在 app 最前面，覆盖所有路由。
 * skip(isTest) 保证主测试套件不被它打死。
 */
export const globalLimiter = rateLimit({
  windowMs: 60_000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  skip,
  keyGenerator: ipKeyGenerator, // 全局限流按 IP（未认证路由用 userId 没意义）
});

/**
 * Auth 限流器：5 req/min/IP。挂在 /api/auth 路由前缀。
 * 比全局严——防爆破。Phase 4 验收：登录连续 6 次错误密码 → 第 6 次 429。
 */
export const authLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skip,
  keyGenerator: ipKeyGenerator,
});

/**
 * 交易限流器：10 req/min/user。挂在 /api/withdraw + /api/payment。
 * keyGenerator 用 userId（已认证）或 IP（未认证）回退——
 * 未认证请求（没带 JWT 打 /api/withdraw/init）按 IP 限流，仍能挡刷子。
 */
export const txLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skip,
  keyGenerator: userKeyGenerator,
});

export { isTest };
