-- 005_bank_keys_rebuild.sql — Phase 3: 重建 bank_keys 表（多密钥轮换）
--
-- v5 §三 3.2 落地：旧 bank_keys 有 CHECK(id=1) 单行约束，SQLite 不能
-- ALTER TABLE 删 CHECK，必须重建表。新表支持多行（密钥轮换：旧密钥
-- status='retired'，新密钥 status='active'）。
--
-- 新增列：
--   key_version   — 密钥版本号（UNIQUE），token v2 schema 的 key_id 对应此列
--   status        — 'active'（当前签发密钥）或 'retired'（已轮换的旧密钥）
--   retired_until — 旧密钥宽限期截止时间（now+90d），超期后旧 token 验签 → 403
--   retired_at    — 密钥轮换时间戳
--
-- 私钥加密：private_key 列从 Phase 0 的明文（32 字节）改为 AES-256-GCM
-- 密文（60 字节 = nonce[12] + ciphertext[32] + tag[16]）。迁移脚本只拷贝
-- 旧数据（仍为明文），bankKeyService 首次启动时检测 32 字节明文 → 加密
-- 回写为 60 字节密文（自愈式升级）。
--
-- 标准重建模式（参考 003_users_role_add_admin.sql）：
--   PRAGMA foreign_keys = OFF;
--   BEGIN;
--   CREATE TABLE bank_keys_new (...);
--   INSERT INTO bank_keys_new ... SELECT ... FROM bank_keys;
--   DROP TABLE bank_keys;
--   ALTER TABLE bank_keys_new RENAME TO bank_keys;
--   COMMIT;
--   PRAGMA foreign_keys = ON;
--   PRAGMA foreign_key_check;

-- Safety guard: if bank_keys doesn't exist (legacy dev DB that skipped
-- baseline — only had users table), create it empty with old schema so the
-- rebuild below can DROP + RENAME without "no such table" errors.
CREATE TABLE IF NOT EXISTS bank_keys (
    id            INTEGER PRIMARY KEY,
    public_key    BLOB,
    private_key   BLOB,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK(id = 1)
);

PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE bank_keys_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key_version   INTEGER UNIQUE NOT NULL,
    public_key    BLOB NOT NULL,             -- 33-byte compressed P = xG
    private_key   BLOB NOT NULL,             -- AES-256-GCM 密文（60 字节）或迁移期明文（32 字节）
    status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','retired')),
    retired_until DATETIME,                 -- 旧密钥宽限期截止（status='retired' 时有效）
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    retired_at    DATETIME                   -- 密钥轮换时间（status='retired' 时有效）
);
-- 拷贝旧数据：旧 id=1 行 → key_version=1, status='active'
-- private_key 保持原样（明文），bankKeyService 首次启动时加密回写
-- 如果旧表为空（legacy DB 从未生成密钥），INSERT 0 行——新表为空，
-- bankKeyService 首次启动时 getOrGenerate() 会生成新密钥。
INSERT INTO bank_keys_new (key_version, public_key, private_key, status)
    SELECT 1, public_key, private_key, 'active' FROM bank_keys WHERE id = 1;
DROP TABLE bank_keys;
ALTER TABLE bank_keys_new RENAME TO bank_keys;
COMMIT;
PRAGMA foreign_keys = ON;
PRAGMA foreign_key_check;  -- 应返回空集
