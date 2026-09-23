-- 009_transactions_add_redeem_split_kind.sql
-- Phase 6.2: 扩展 transactions.kind CHECK 约束增加 'redeem_split'
--
-- v6 §四 6.2 落地：redeemSplit 服务在 transactions 表写流水时 kind='redeem_split'，
-- 以便 /history 页面区分"找零兑付"与"商户收款"。但 baseline 001 的 CHECK
-- 约束只允许 ('withdraw','deposit','refund')，导致 INSERT 失败抛
-- "CHECK constraint failed: kind IN ('withdraw','deposit','refund')"。
--
-- SQLite 不支持 ALTER TABLE 修改 CHECK 约束，必须重建表。标准做法
-- （参考 SQLite 文档 §"Making Other Kinds Of Table Schema Changes"）：
--   1. CREATE TABLE transactions_new (扩展 CHECK)
--   2. INSERT INTO transactions_new SELECT * FROM transactions（保留数据）
--   3. DROP TABLE transactions
--   4. ALTER TABLE transactions_new RENAME TO transactions
--   5. 重建索引
--
-- 整个迁移在事务中执行（migrationRunner 已 BEGIN IMMEDIATE），任何步骤失败
-- 整体回滚，不会丢数据。

-- 1. 新表结构（CHECK 约束扩展为 4 种 kind）
CREATE TABLE IF NOT EXISTS transactions_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    kind          TEXT NOT NULL CHECK(kind IN ('withdraw','deposit','refund','redeem_split')),
    amount        INTEGER NOT NULL,
    counterparty  TEXT,
    serial        BLOB,
    session_id    TEXT,
    note          TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 2. 复制现有数据（如果 baseline 001 已建表并有数据）
--    SQLite 不支持 INSERT IF NOT EXISTS，用 INSERT OR IGNORE 兜底。
INSERT OR IGNORE INTO transactions_new
    (id, user_id, kind, amount, counterparty, serial, session_id, note, created_at)
SELECT
    id, user_id, kind, amount, counterparty, serial, session_id, note, created_at
FROM transactions;

-- 3. 删除旧表
DROP TABLE IF EXISTS transactions;

-- 4. 重命名
ALTER TABLE transactions_new RENAME TO transactions;

-- 5. 重建索引（DROP TABLE 已删了 idx_tx_user_time，需要重建）
CREATE INDEX IF NOT EXISTS idx_tx_user_time ON transactions(user_id, created_at DESC);
