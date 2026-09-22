// utils/logger.js — Phase 1: minimal logger (N1 fallback for invariant alerts)
//
// v5 §三 1.1 N1 修正：assertInvariant 失败时用 logger.error 兜底——audit_log
// 表 Phase 3 才建，Phase 1 不能依赖它。Phase 3 建好 audit_log 后把
// logger.error 改写为 auditService.logAction({action:'invariant_violation', ...})。
//
// Phase 5 (工程化) 会把整个 logger 换成 pino-http（结构化日志 + auto
// request_id）。本文件只是过渡，调用方代码不需改——只是 logger.error /
// logger.info / logger.warn 的实现换了。
//
// 设计选择：console.error/warn/info 是 Node.js 同步写入 stderr/stdout，
// 对教学系统够用。生产换 pino 时一并改造。

export const logger = {
  error: (obj) => {
    if (typeof obj === 'string') console.error('[ERROR]', obj);
    else console.error('[ERROR]', JSON.stringify(obj));
  },
  warn: (obj) => {
    if (typeof obj === 'string') console.warn('[WARN]', obj);
    else console.warn('[WARN]', JSON.stringify(obj));
  },
  info: (obj) => {
    if (typeof obj === 'string') console.info('[INFO]', obj);
    else console.info('[INFO]', JSON.stringify(obj));
  },
};
