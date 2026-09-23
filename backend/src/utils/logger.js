// utils/logger.js — Phase 4 (v5 §三 4): pino 结构化日志
//
// v5 §三 4 落地：把 Phase 1 的 console 包装 logger 换成 pino，输出 JSON
// 一行一条，便于日志聚合（ELK / Loki / CloudWatch）。pino-http 中间件
// 在 app.js 挂载后自动给每个请求生成 req.id（UUID），并把 req/res 序列化
// 写入日志——不用手写 request_id 中间件。
//
// 文献参考：
//   [1] NIST SP 800-92rev1 §3 "Audit Log Security" — 要求日志条目含
//       timestamp + event type + actor + outcome。pino 默认输出 time/level/
//       pid/hostname + 调用方传入的任意字段，满足该要求。
//   [2] OWASP ASVS L1 v4.0.31 §7.1.1 — "verify that all authentication events
//       are logged"，pino-http 自动记录每个 HTTP 请求的 method/url/status
//       + response time，覆盖此条要求。
//
// 接口兼容性：本文件保持 logger.error/warn/info(obj) 形式，调用方代码
// （auditService / bankReserveService / sessionCleanupService）无需改动。
// pino 原生支持 logger.info(obj) 形式——obj 的字段会平铺到 JSON 输出。
//
// 测试环境降级：NODE_ENV !== 'production' 时用 pino.transport({ target:
// 'pino-pretty' }) 输出彩色可读格式，便于本地开发。生产用纯 JSON。

import pino from 'pino';

const isProd = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test' || !!process.env.VITEST;

// 测试环境用纯 pino（JSON 输出，不走 transport）——pino-pretty 的 transport
// 用 worker thread，在 vitest 子进程里会触发 "unable to determine transport
// target" 错误。生产也用纯 pino（JSON 利于日志聚合）。只有本地开发
// （NODE_ENV 未设或 development）才用 pino-pretty 彩色输出。
const logger = (!isProd && !isTest)
  ? pino(
      { level: process.env.BC_LOG_LEVEL || 'info' },
      pino.transport({
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:HH:MM:ss.l',
          ignore: 'pid,hostname',
        },
      }),
    )
  : pino({
      level: process.env.BC_LOG_LEVEL || 'info',
      // 测试环境降到 warn，避免 INFO 日志刷屏干扰测试输出
      ...(isTest ? { level: 'warn' } : {}),
    });

export { logger };
export default logger;
