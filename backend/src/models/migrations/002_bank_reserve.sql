-- 002_bank_reserve.sql — Phase 1: 银行准备金账本（M1 修正后的正确模型）
--
-- v5 §三 1.1 落地：bank_reserve 单行 singleton 表，跟踪 total_issued /
-- total_redeemed / reserve_balance。所有 balance/reserve 变更的操作
-- （init/submit/reveal/cancel/expire/lazy-cleanup/deposit/redeem/payment）
-- 在 runImmediateTx 末尾调 assertInvariant(db) 验证不变量成立。
--
-- M1 修正后的核心不变量（含在途项）：
--   reserve_balance == SUM(users.balance)
--                    + (total_issued − total_redeemed)
--                    + SUM(amount WHERE withdrawal_sessions.status
--                           IN ('pending','submitted'))
--
-- 否则 init/reveal 之间的 5min TTL 窗口期会假阳性触发（init 已 debit
-- 余额但 reveal 还没签发，原公式漏在途项会让 reserve == SUM(balance)
-- + (issued − redeemed) 不成立）。
--
-- 表结构：singleton 单行（CHECK(id=1)），启动时 INSERT OR IGNORE id=1。

CREATE TABLE IF NOT EXISTS bank_reserve (
    id              INTEGER PRIMARY KEY CHECK(id = 1),
    total_issued    INTEGER NOT NULL DEFAULT 0,  -- 累计已发行电子货币
    total_redeemed  INTEGER NOT NULL DEFAULT 0,  -- 累计已回收电子货币
    reserve_balance INTEGER NOT NULL DEFAULT 0,  -- 准备金（法币等额担保）
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO bank_reserve (id) VALUES (1);
