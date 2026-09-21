-- BlindCash DDL (SQLite, WAL mode) — M1
--
-- M1 scope: ONLY the users table (identity + role + fiat balance).
-- Later milestones add:
--   bank_keys            (M2 — bank signing key pair)
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
