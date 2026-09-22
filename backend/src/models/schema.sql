-- BlindCash DDL (SQLite, WAL mode) — M1 + M3
--
-- M1 scope: users table (identity + role + fiat balance).
-- M3 scope: bank_keys table (singleton bank signing keypair).
-- Later milestones add:
--   withdrawal_sessions  (M4 — 4-move protocol state machine)
--   spent_coins          (M5 — double-spend detection)
--
-- Design notes (v3 §3.3 invariants, see ISOLATION.md):
--   * role is CHECK-constrained to ('customer','merchant') — mutually exclusive.
--   * balance is the fiat account balance:
--       customer.balance is ONLY decremented by /withdraw/* (init debits,
--         cancel/refund credits back).
--       merchant.balance is ONLY incremented by /payment.
--   * There is NO numeric-satoshi-vs-yuan ambiguity at M1: balance is an
--     integer in the smallest unit; presentation formatting is a UI concern.

PRAGMA journal_mode = WAL;       -- concurrent reads + serialized writes
PRAGMA foreign_keys = ON;         -- enforce FK constraints

-- ── 身份层：用户（假名 + 密码 + 角色 + 法币余额） ──
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,           -- pseudonym, NOT real name
    password_hash TEXT NOT NULL,                  -- bcrypt hash (rounds=12)
    role          TEXT NOT NULL CHECK(role IN ('customer','merchant')),
    balance       INTEGER NOT NULL DEFAULT 0,     -- fiat account balance (smallest unit)
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── 密钥层：银行签名密钥（单行，启动时生成） ──
-- ⚠ 教学演示用：私钥明文存 DB。生产应加密 / HSM / Shamir 分片——密钥安全是另一独立维度。
-- ⚠ 测试不应依赖读 private_key 证明任何事（密钥泄露属于密钥安全维度，非协议维度）。
--   (ISOLATION.md §五 不变量 7)
CREATE TABLE IF NOT EXISTS bank_keys (
    id            INTEGER PRIMARY KEY,
    public_key   BLOB NOT NULL,            -- 33-byte compressed P = xG
    private_key   BLOB NOT NULL,           -- 32-byte x
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    CHECK(id = 1)                            -- singleton
);
