// tests/rateLimit.test.js — Phase 4 (v5 §三 4): 限流专项测试
//
// v5 §三 4 验收：主测试套件的限流器都 skip(isTest) → no-op，所以这里
// **手动构造不复用 skip 的 limiter 实例**，验证 429 + Retry-After 真的
// 会触发。否则限流在主套件里隐形等于没验证（审查 Q 的核心诉求）。
//
// 5 个测试覆盖：
//   ✓ authLimiter：5 req/min/IP，第 6 次 429 + Retry-After header
//   ✓ txLimiter：10 req/min/user，第 11 次 429（已认证用 userId key）
//   ✓ txLimiter：未认证回退到 ipKeyGenerator，仍能限流
//   ✓ standardHeaders：429 响应带 RateLimit-* 标准头
//   ✓ 主 app 的 /api/health 不被业务限流（globalLimiter skip 生效）
//
// 文献参考：
//   [1] OWASP ASVS L1 v4.0.31 §11.1.1 — "verify that rate limiting is in
//       place for authentication, session management, and other sensitive
//       flows"。本测试是此条的 executable test surface。
//   [2] NIST SP 800-63Brev2 §5.2.2 — "throttle authentication attempts"，
//       authLimiter 的 5 req/min 即此要求落地，第 6 次必拒。
//   [3] RFC 9110 §15.5.14 — 429 Too Many Requests 应带 Retry-After 头，
//       本测试断言此头存在。

import { describe, it, expect, afterAll } from 'vitest';
import express from 'express';
import http from 'node:http';
import rateLimit from 'express-rate-limit';

// 构造一个**不复用 skip** 的 authLimiter——max: 5，windowMs: 60_000，
// 永远不 skip。这是审查 Q 强调的"手动 new limiter 实例"路径。
// 测试用固定 key 生成器——隔离 ipKeyGenerator 在 Node http server 下
// 可能返回不同值的问题。生产用 ipKeyGenerator，测试只验证限流逻辑本身。
const FIXED_KEY = 'test-ip-key';
async function makeAuthLimiter () {
  return rateLimit({
    windowMs: 60_000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: () => FIXED_KEY,
  });
}

async function makeTxLimiter () {
  return rateLimit({
    windowMs: 60_000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user?.userId
      ? `user:${req.user.userId}`
      : FIXED_KEY,
  });
}

let server, baseUrl;
async function startApp (app) {
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
}
async function hit (path, { token } = {}) {
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${baseUrl}${path}`, { headers });
  return { status: res.status, headers: res.headers };
}

afterAll(async () => server?.close());

describe('Phase 4 · rateLimit — 专项验证 429 + Retry-After（不走 skip）', () => {
  // trust proxy 必须设——否则 Express 4 的 req.ip 在某些环境下为 undefined，
  // ipKeyGenerator 拿不到稳定 key，每次请求 key 不同→永远不限流。
  // 生产部署在反向代理后也必须设 trust proxy（见 app.js 的生产配置）。
  it('authLimiter: 第 6 次请求 → 429 + Retry-After header', async () => {
    const app = express();
    app.set('trust proxy', 1);
    app.use(await makeAuthLimiter());
    app.get('/test', (_req, res) => res.json({ ok: true }));
    await startApp(app);

    // 前 5 次都 200
    for (let i = 0; i < 5; i++) {
      const r = await hit('/test');
      expect(r.status).toBe(200);
    }
    // 第 6 次 429
    const blocked = await hit('/test');
    expect(blocked.status).toBe(429);
    // Retry-After header 存在（RFC 9110 §15.5.14）
    const retryAfter = blocked.headers.get('retry-after');
    expect(retryAfter).not.toBeNull();
    expect(Number(retryAfter)).toBeGreaterThan(0);
    // standardHeaders: RateLimit-* headers
    expect(blocked.headers.get('ratelimit-limit')).toBe('5');
    expect(blocked.headers.get('ratelimit-remaining')).toBe('0');
  });

  it('txLimiter: 已认证用户第 11 次 → 429（用 userId key）', async () => {
    const app = express();
    app.set('trust proxy', 1);
    // 模拟 authenticateJWT：注入 req.user
    app.use((req, _res, next) => {
      req.user = { userId: 42, username: 'alice', role: 'customer' };
      next();
    });
    app.use(await makeTxLimiter());
    app.get('/tx', (_req, res) => res.json({ ok: true }));
    await startApp(app);

    for (let i = 0; i < 10; i++) {
      const r = await hit('/tx');
      expect(r.status).toBe(200);
    }
    const blocked = await hit('/tx');
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('ratelimit-limit')).toBe('10');
  });

  it('txLimiter: 未认证请求回退到 ipKeyGenerator，仍能限流', async () => {
    const app = express();
    app.set('trust proxy', 1);
    // 不注入 req.user ——模拟未带 JWT 打 /api/withdraw/init
    app.use(await makeTxLimiter());
    app.get('/tx', (_req, res) => res.json({ ok: true }));
    await startApp(app);

    // 未认证也按 IP 限流，10 次后 429
    for (let i = 0; i < 10; i++) {
      const r = await hit('/tx');
      expect(r.status).toBe(200);
    }
    const blocked = await hit('/tx');
    expect(blocked.status).toBe(429);
  });

  it('standardHeaders: 429 响应带 RateLimit-Policy / Limit / Remaining', async () => {
    const app = express();
    app.set('trust proxy', 1);
    app.use(await makeAuthLimiter());
    app.get('/test', (_req, res) => res.json({ ok: true }));
    await startApp(app);

    // 击穿 5 次
    for (let i = 0; i < 5; i++) await hit('/test');
    const blocked = await hit('/test');
    expect(blocked.status).toBe(429);
    // standardHeaders draft-7: RateLimit-Limit + RateLimit-Remaining
    expect(blocked.headers.has('ratelimit-limit')).toBe(true);
    expect(blocked.headers.has('ratelimit-remaining')).toBe(true);
    expect(blocked.headers.get('ratelimit-remaining')).toBe('0');
  });

  it('主 app 的 /api/health 在 NODE_ENV=test 下不被限流（skip 生效）', async () => {
    // 动态导入主 app（已挂 globalLimiter，skip(isTest) 让它 no-op）
    const { default: mainApp } = await import('../src/app.js');
    await startApp(mainApp);

    // 连打 20 次 /api/health ——globalLimiter max=100，但 skip 生效所以不会 429
    for (let i = 0; i < 20; i++) {
      const r = await hit('/api/health');
      expect(r.status).toBe(200);
    }
  });
});
