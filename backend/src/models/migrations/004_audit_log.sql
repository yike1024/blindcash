-- 004_audit_log.sql — Phase 3: 审计日志表
--
-- v5 §三 3.3 落地：audit_log 记录所有关键操作（密钥轮换/充值/退币/取款/
-- 支付/不变量违反），管理员可分页查询。
--
-- N1 死锁修正落地：Phase 1 用 logger.error/logger.info 兜底，Phase 3
-- 建本表后升级为 auditService.logAction。assertInvariant 失败路径写
-- 'invariant_violation' action（M1 配套）。
--
-- 表结构：
--   actor_id   — 操作发起者 user id（系统操作可为 NULL）
--   action     — 操作类型枚举（不设 CHECK 约束，便于扩展新 action）
--   target     — 操作目标（如 session_id / serial hex / key_version）
--   amount     — 涉及金额（可为 NULL）
--   meta       — JSON 字符串，附加上下文
--   ip_address — 请求来源 IP
--
-- 无外键约束：audit_log 是 append-only 历史记录，不应因 user 被删除而
-- 级联删除审计记录（保留审计痕迹是合规要求）。

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id    INTEGER,
    action      TEXT NOT NULL,
    target      TEXT,
    amount      INTEGER,
    meta        TEXT,
    ip_address  TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_log(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor_time ON audit_log(actor_id, created_at DESC);
