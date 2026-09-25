-- 002_bank_reserve.sql — Phase 1: 银行准备金账本 (PostgreSQL)
--
-- bank_reserve 单行 singleton 表，跟踪 total_issued / total_redeemed /
-- reserve_balance。CHECK(id = 1) 保证只有一行。

CREATE TABLE IF NOT EXISTS bank_reserve (
    id              INTEGER PRIMARY KEY CHECK(id = 1),
    total_issued    INTEGER NOT NULL DEFAULT 0,
    total_redeemed  INTEGER NOT NULL DEFAULT 0,
    reserve_balance INTEGER NOT NULL DEFAULT 0,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO bank_reserve (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
