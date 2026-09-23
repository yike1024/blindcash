-- 007_bank_keys_add_denomination.sql — Phase 6.1: 多面额密钥
--
-- 不同面额 (1/5/10/50/100 BC) 用不同签名密钥。每个面额同时只有一个
-- active 密钥（partial unique index 保证），密钥轮换时旧密钥 status='retired'
-- 新密钥 status='active'，两者不冲突。
--
-- 前向兼容：denomination DEFAULT 1，旧数据自动归为面额 1。
-- withdrawal_sessions 和 spent_coins 的 denomination 列在 008 迁移中添加。

ALTER TABLE bank_keys ADD COLUMN denomination INTEGER NOT NULL DEFAULT 1;

-- Partial unique index: 每个面额同时只能有一个 active 密钥。
-- 当 rotateKey(denom) 时：旧密钥先 UPDATE status='retired'，再 INSERT
-- 新密钥 status='active'——两步不在同一事务中也不冲突（retired 行不
-- 在 partial index 范围内）。
CREATE UNIQUE INDEX IF NOT EXISTS idx_bk_active_denom
    ON bank_keys(denomination) WHERE status = 'active';
