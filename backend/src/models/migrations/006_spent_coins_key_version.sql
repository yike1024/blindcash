-- 006_spent_coins_key_version.sql — Phase 3: spent_coins 加 key_version 列
--
-- v5 §三 3.2 落地：spent_coins 记录每枚已花费 token 是用哪个 key_version
-- 签发的。密钥轮换后：
--   - 新 token 用新 key_version 签发，支付时 INSERT key_version = 新版本
--   - 旧 token 拿 key_id（= 旧 key_version）查旧公钥验签，支付时 INSERT
--     key_version = 旧版本
--
-- key_version 允许 NULL：迁移前已存在的 spent_coins 行没有此信息
--（前向兼容）。bankKeyService.getPublicKeyByVersion(v) 在 v 为 NULL 时
-- 走 getActivePublicKey() fallback（paymentService 已实现此逻辑）。

-- Safety guard: if spent_coins doesn't exist (legacy dev DB that skipped
-- baseline — only had users table), create it empty with the original schema
-- so the ALTER TABLE below doesn't raise "no such table". This mirrors the
-- pattern used by 005_bank_keys_rebuild.sql for bank_keys.
CREATE TABLE IF NOT EXISTS spent_coins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    serial      BLOB NOT NULL UNIQUE,
    spent_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE spent_coins ADD COLUMN key_version INTEGER;
