-- 008_add_denomination_to_sessions_and_spent_coins.sql — Phase 6.1 + 6.3
--
-- withdrawal_sessions 加 denomination 列：reveal 时需要知道用哪个面额的
-- 密钥签名（init 时选定，reveal 时从 session 行读出）。
--
-- spent_coins 加 denomination 列：6.3 匿名集分析按 (denomination, key_version)
-- 分组统计——相同面额相同版本号的 token 在银行视角下不可区分。
--
-- 前向兼容：DEFAULT 1，旧数据自动归为面额 1。

-- Safety guard: if withdrawal_sessions doesn't exist (legacy dev DB that skipped
-- baseline — only had users table), create it empty with the original schema
-- so the ALTER TABLE below doesn't raise "no such table". This mirrors the
-- pattern used by 006_spent_coins_key_version.sql for spent_coins.
CREATE TABLE IF NOT EXISTS withdrawal_sessions (
    id            TEXT PRIMARY KEY,
    customer_id   INTEGER NOT NULL,
    amount        INTEGER NOT NULL,
    n_candidates  INTEGER NOT NULL,
    candidates    TEXT NOT NULL,
    j_index       INTEGER,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','submitted','committed','aborted','cancelled','expired')),
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME NOT NULL
);

-- Safety guard: if spent_coins doesn't exist (legacy dev DB), create it empty.
-- 006_spent_coins_key_version.sql also has this guard, but if 006 was somehow
-- skipped (e.g., older DB), we still need it here.
CREATE TABLE IF NOT EXISTS spent_coins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    serial      BLOB NOT NULL UNIQUE,
    amount      INTEGER NOT NULL,
    deposited_to INTEGER NOT NULL,
    token_hash  BLOB NOT NULL,
    spent_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE withdrawal_sessions ADD COLUMN denomination INTEGER NOT NULL DEFAULT 1;
ALTER TABLE spent_coins ADD COLUMN denomination INTEGER NOT NULL DEFAULT 1;
