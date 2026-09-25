-- 010_payment_escrows.sql — Phase 7: 在线托管与收款单防抢兑 (PostgreSQL)
--
-- 对应教授 A 与 教授 B 审查意见：
--   1. 两案合一：payment_escrows 同时支持收款单 challenge 与两阶段托管。
--   2. merchant_id 由服务端根据登录者硬编码，不可由客户端指定。
--   3. serial 具备 UNIQUE 约束，防止同一个 token 被锁定到多个单据。
--   4. 状态机：created → locked → committed | cancelled | expired。
--
-- 状态流转规则：
--   - created: 商户创建收款单，等待顾客扫码/填单
--   - locked: 顾客将 token 锁定给该单（此时 token 入 spent_coins 防双花，进入在途托管）
--   - committed: 顾客确认收货，资金划入商户 balance
--   - cancelled: 协商取消，资金以法币退回顾客 balance
--   - expired: 超时未付款或未确认，触发懒清理退回

CREATE TABLE IF NOT EXISTS payment_escrows (
    id            TEXT PRIMARY KEY,               -- UUIDv4 (escrow_id)
    merchant_id   INTEGER NOT NULL,               -- 商户 ID（服务端写入，不可篡改）
    customer_id   INTEGER,                        -- 锁定 token 的顾客 ID
    amount        INTEGER NOT NULL CHECK(amount > 0),
    denomination  INTEGER NOT NULL DEFAULT 1,
    challenge     TEXT NOT NULL UNIQUE,           -- 32-byte hex nonce，防重放
    serial        BYTEA UNIQUE,                   -- 锁定的 token serial，单币唯一锁定
    token_hash    BYTEA,                          -- 锁定的 token SHA256 哈希
    status        TEXT NOT NULL DEFAULT 'created'
                  CHECK(status IN ('created','locked','committed','cancelled','expired')),
    expires_at    TIMESTAMP NOT NULL,             -- 支付与确认时效
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locked_at     TIMESTAMP,
    committed_at  TIMESTAMP,
    cancelled_at  TIMESTAMP,
    FOREIGN KEY (merchant_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_pe_merchant_status ON payment_escrows(merchant_id, status);
CREATE INDEX IF NOT EXISTS idx_pe_customer_status ON payment_escrows(customer_id, status);
CREATE INDEX IF NOT EXISTS idx_pe_expires_status  ON payment_escrows(expires_at, status);
