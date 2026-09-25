// BlindCash backend entry — M1 + M3 + M4 + M5 + M7 + Phase 4 + Phase 5
//
// M1 scope: health check + auth routes (register/login with role).
// M3 scope: bank keypair provisioning on boot + GET /api/bank/pubkey.
// M4 scope: 4-move withdrawal protocol (init/submit/reveal/cancel).
// M5 scope: payment endpoint (POST /api/payment).
// M7 scope: transactions 账本表 + GET /api/transactions + 角色解锁闭环.
// Phase 4: pino-http 结构化日志（auto req_id）+ express-rate-limit 三级限流。
// Phase 5: Docker 部署（express.static 托管前端 dist）+ Swagger UI（/api/docs）。

import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pinoHttp from 'pino-http';
import { getDb, closeDb } from './models/db.js';
import { runMigrations } from './utils/migrationRunner.js';
import { getOrGenerate } from './services/bankKeyService.js';
import { startCleanupJob } from './services/sessionCleanupService.js';
import { bytesToHex } from './utils/hex.js';
import { logger } from './utils/logger.js';
import { globalLimiter, authLimiter, txLimiter } from './middleware/rateLimit.js';

import authRoutes from './routes/auth.js';
import bankRoutes from './routes/bank.js';
import withdrawalRoutes from './routes/withdrawal.js';
import paymentRoutes from './routes/payment.js';
import transactionsRoutes from './routes/transactions.js';
import adminRoutes from './routes/admin.js';
import privacyRoutes from './routes/privacy.js';

// Phase 5: resolve paths for serving the built frontend + openapi spec.
const __dirname = dirname(fileURLToPath(import.meta.url));
// backend/src/app.js → backend/ → blindcash/ → frontend/dist
const FRONTEND_DIST = join(__dirname, '..', '..', 'frontend', 'dist');
// openapi.yaml lives at blindcash/docs/openapi.yaml
const OPENAPI_PATH = join(__dirname, '..', '..', 'docs', 'openapi.yaml');

// NOTE: blindcash uses port 4100 (NOT 4000) so it can run side-by-side with
// the cryptobank project (which uses 4000). The Vite dev server runs on 5174
// (cryptobank uses 5173) and proxies /api → localhost:4100.
const app = express();
const PORT = process.env.PORT || 4100;

// trust proxy 1：生产部署在 nginx/Caddy 反向代理后，req.ip 必须从
// X-Forwarded-For 取——否则 ipKeyGenerator 拿不到真实客户端 IP，
// globalLimiter 会把所有请求当成代理的 IP 限流，误伤/绕过并存。
app.set('trust proxy', 1);

// CORS: 允许本地开发 + 已部署的前端域名。
// 生产环境可通过 CORS_ORIGIN 环境变量配置（逗号分隔，或设为 * 允许全部）。
const CORS_ALLOWED = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const DEFAULT_ORIGINS = [
  'http://localhost:5174',
  'http://127.0.0.1:5174',
  'https://blindcash-tabs.surge.sh',
];
const allowedOrigins = CORS_ALLOWED.length ? CORS_ALLOWED : DEFAULT_ORIGINS;
app.use(cors({
  origin(origin, cb) {
    // 允许无 origin 的请求（curl/Postman）以及白名单内的来源
    if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      cb(null, true);
    } else {
      cb(null, false);
    }
  },
}));
app.use(express.json({ limit: '1mb' }));

// Phase 4 (v5 §三 4)：pino-http 自动给每个请求生成 req.id（UUID v4），
// 并把 req/res 序列化写入日志（method/url/status/response_time）。
// customReqId 兼容已有中间件读 req.id 的写法。
app.use(pinoHttp({
  logger,
  genReqId: (_req, res) => {
    if (!res.req.id) {
      res.req.id = crypto.randomUUID();
    }
    return res.req.id;
  },
  // 不记录 /api/health 的请求日志（健康检查刷屏）——只记录业务路径。
  autoLogging: {
    ignore: (req) => req.url === '/api/health',
  },
}));

// Phase 4：全局限流（100 req/min/IP）——挂在最前面，所有路由都过它。
// skip(isTest) 让 NODE_ENV=test 时限流器变 no-op，不打死 168 个测试。
app.use(globalLimiter);

/**
 * Initialize DB schema via migrations + ensure the bank signing keypair exists.
 * Called ONLY when the server actually starts (app.listen), NOT at module
 * import time — so test files that import app for supertest don't initialize
 * the DB before DATABASE_URL is set (tests manage their own schema via
 * resetTestDb in beforeAll).
 *
 * Phase 0 (v5 §二 H1): now calls runMigrations() directly instead of the
 * legacy initSchema() — same effect, more explicit. On failure, throws and
 * the caller (app.listen path below) lets the process exit with non-zero.
 *
 * M3 addition: after runMigrations(), call bankKeyService.getOrGenerate() to
 * provision the singleton row in bank_keys. On first boot this generates a
 * fresh keypair; on subsequent boots it reads the existing row back (no
 * regeneration — would invalidate previously-issued tokens).
 *
 * Phase 1 缺陷修复 (方案 A): after runMigrations() + getOrGenerate(), start
 * the global session cleanup job. It scans expired sessions hourly and
 * refunds them so in-flight amounts don't hang forever. The returned stop()
 * is registered on SIGINT/SIGTERM so the interval is cleared on graceful
 * shutdown.
 */
export async function initDatabase() {
  await closeDb();
  const db = getDb();
  await runMigrations(db);
  const kp = await getOrGenerate();
  logger.info({ event: 'bank_key_loaded', public_key: bytesToHex(kp.publicKey) },
    'Bank signing keypair loaded');

  const stopCleanup = startCleanupJob();
  process.on('SIGINT', stopCleanup);
  process.on('SIGTERM', stopCleanup);
}

// Health check (namespaced under /api for consistency with the Vite proxy)
// Phase 4：不上业务限流（health 被限流会误报服务挂掉），但 pino-http 的
// autoLogging.ignore 已跳过它的请求日志。
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'blindcash-backend', milestone: 'M7' });
});

// Auth routes (register + login — both accept/return a role)
// Phase 4：authLimiter（5 req/min/IP）防爆破，挂在 authenticateJWT 之前。
app.use('/api/auth', authLimiter, authRoutes);

// Bank public routes (M3): GET /api/bank/pubkey — no auth, lets anyone fetch
// the bank's public key P for local signature verification.
app.use('/api/bank', bankRoutes);

// Withdrawal routes (M4/M7): 4-move protocol — any logged-in user can withdraw
// (role lock removed for Chaum-style transfer closure).
// Phase 4：txLimiter（10 req/min/user）挂在 authenticateJWT 之后——
// req.user.userId 必须先由 authenticateJWT 设置，否则 keyGenerator 拿不到
// userId 会 fallback 到 IP，触发 express-rate-limit v7+ 的 ipv6Subnet 警告。
// 这里只对 /withdraw 整路由前缀挂载，子路由各自再 authenticateJWT。
app.use('/api/withdraw', txLimiter, withdrawalRoutes);

// Payment routes (M5/M7): POST /api/payment deposits a withdrawn token to any
// logged-in user's balance. Format gate + verifySig + atomic runImmediateTx
// live in paymentService.js.
app.use('/api/payment', txLimiter, paymentRoutes);

// Transactions routes (M7): GET /api/transactions — current user's ledger.
app.use('/api/transactions', transactionsRoutes);

// Admin routes (Phase 3): GET /api/admin/audit + POST /api/admin/rotate-key
app.use('/api/admin', adminRoutes);

// Privacy routes (Phase 6.3): POST /api/privacy/report — anonymity set analysis
app.use('/api/privacy', privacyRoutes);

// Phase 5: API 文档端点。
// GET /api/openapi.yaml — 返回 OpenAPI 3.1 规范文件（供 Swagger UI 加载）。
// GET /api/docs — 返回 Swagger UI HTML，从 CDN 加载 swagger-ui-dist 并指向
// /api/openapi.yaml。用 CDN 而非 npm 依赖是为了避免 swagger-ui-express
// 引入 ~5MB 静态资源到镜像，且生产环境通常有外网；离线环境可改为本地托管。
app.get('/api/openapi.yaml', (_req, res) => {
  res.sendFile(OPENAPI_PATH);
});
app.get('/api/docs', (_req, res) => {
  res.type('html').send(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>BlindCash API · Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      window.ui = SwaggerUIBundle({
        url: '/api/openapi.yaml',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
      });
    };
  </script>
</body>
</html>`);
});

// Phase 5: 托管前端构建产物（frontend/dist）。
// express.static 挂在所有 /api 路由之后——API 路由优先匹配，前端路由
// （/login、/wallet 等）由下面的 SPA catch-all 返回 index.html。
// 如果 frontend/dist 不存在（开发模式，前端走 vite dev server 5174），
// express.static 会 404，不影响 API。
app.use(express.static(FRONTEND_DIST));

// SPA catch-all：所有非 /api 的 GET 请求返回 index.html，让 React Router
// 接管客户端路由。POST/PUT/DELETE 等非 API 请求返回 404（不属于前端路由）。
app.get(/^\/(?!api).*/, (_req, res, next) => {
  const indexHtml = join(FRONTEND_DIST, 'index.html');
  res.sendFile(indexHtml, (err) => {
    if (err) {
      // frontend/dist 不存在（开发模式），让错误中间件处理
      next(err);
    }
  });
});

// Phase 4：兜底错误中间件——所有未捕获的异常走这里，带 req_id 便于追溯。
// 必须挂在所有路由之后（Express 错误中间件的 arity 4 约定）。
app.use((err, req, res, _next) => {
  const status = err.status || 500;
  logger.error({
    err: { name: err.name, message: err.message, stack: err.stack },
    req_id: req.id,
    method: req.method,
    url: req.url,
    status,
  }, 'unhandled_error');
  res.status(status).json({
    error: status >= 500 ? 'INTERNAL_ERROR' : (err.code || 'ERROR'),
    message: status >= 500 ? 'Internal server error' : err.message,
    req_id: req.id,
  });
});

// Only start the HTTP server when running as the main entry (not when
// imported by test files — supertest creates its own server from app).
if (process.env.NODE_ENV !== 'test') {
  initDatabase()
    .then(() => {
      app.listen(PORT, () => {
        logger.info({ event: 'server_listening', port: PORT },
          `BlindCash API listening on http://localhost:${PORT}`);
      });
    })
    .catch((err) => {
      logger.error({ event: 'init_failed', error: err.message, stack: err.stack });
      process.exit(1);
    });
}

export default app;
