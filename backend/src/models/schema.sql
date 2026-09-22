-- BlindCash DDL (SQLite, WAL mode) — M1 + M3 + M4 + M5
--
-- M1 scope: users table (identity + role + fiat balance).
-- M3 scope: bank_keys table (singleton bank signing keypair).
-- M4 scope: withdrawal_sessions table (4-move protocol state machine).
-- M5 scope: spent_coins table (double-spend detection, used by /api/payment).
--
-- Design notes (v3 §3.3 invariants, see ISOLATION.md):
--   * role is CHECK-constrained to ('customer','merchant') — mutually exclusive.
--   * balance is the fiat account balance:
--       customer.balance is ONLY decremented by /withdraw/* (init debits,
--         cancel/refund credits back). Initial 100 credited on registration
--         (M5: see userService.js INITIAL_BALANCE_CUSTOMER — 教学用).
--       merchant.balance is ONLY incremented by /payment (M5).
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

-- ── 取款层：4-move 协议会话状态机（M4） ──
-- v3 §2.3 + §3.1: tracks the cut-and-choose withdrawal lifecycle.
-- status ∈ {pending, submitted, committed, aborted, cancelled, expired}:
--   pending   — after ① init, before ③ submit
--   submitted — bank picked j, before ⑤ reveal
--   committed — reveal verified, s_j returned (terminal success)
--   aborted   — cut-and-choose verify failed (refunded)
--   cancelled — user POSTed /cancel before reveal (refunded)
--   expired    — TTL elapsed, lazy-cleanup refunded on next init
--
-- ISOLATION §三 不变量 3 (CRITICAL): the `candidates` JSON column stores
--   {k_i, R_i, e_i, R_prime_i, serial_i, status_i} per candidate but
--   NEVER stores α_i or β_i. The signed candidate j's blinders α_j, β_j
--   never leave the user's device through any API or DB row. The route
--   layer enforces this by 400-ing any submit/reveal payload that contains
--   α/β fields for the wrong index (see withdrawalService.js).
--
-- ISOLATION §三 不变量 4: idx_ws_active_per_customer UNIQUE INDEX enforces
--   at-most-one active (pending|submitted) session per customer at the DB
--   layer — defense-in-depth behind the service-layer check. A second init
--   while one is active raises SQLITE_CONSTRAINT_UNIQUE (caught → 409).
--
-- ISOLATION §三 不变量 5: each session generates N fresh k_i (stored in
--   candidates[i].k) — never reused across sessions. k_i persists so the
--   bank can compute s_j = k_j + e_j·x at reveal time.
CREATE TABLE IF NOT EXISTS withdrawal_sessions (
    id            TEXT PRIMARY KEY,         -- UUIDv4 (crypto.randomUUID)
    customer_id   INTEGER NOT NULL,
    amount        INTEGER NOT NULL,          -- claimed withdrawal amount
    n_candidates  INTEGER NOT NULL,          -- CUT_AND_CHOOSE_N at init time
    candidates    TEXT NOT NULL,             -- JSON array (no α_i/β_i!)
    j_index       INTEGER,                   -- bank-picked j (set at submit)
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','submitted','committed','aborted','cancelled','expired')),
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME NOT NULL,        -- created_at + SESSION_TTL_MS
    FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ws_customer ON withdrawal_sessions(customer_id, status);
-- Defense-in-depth for 不变量 4: at most one active session per customer.
-- The partial UNIQUE index only covers rows whose status is pending|submitted;
-- committed/aborted/cancelled/expired rows are excluded so a user can start a
-- new withdrawal right after the previous one finished.
CREATE UNIQUE INDEX IF NOT EXISTS idx_ws_active_per_customer
    ON withdrawal_sessions(customer_id) WHERE status IN ('pending','submitted');

-- ── 双花检测层：已花费 token（M5 使用，M4 一起建表） ──
-- v3 §3.1 + §四-4: spent_coins holds coins that have been successfully
-- deposited to a merchant. Payment (M5) does BEGIN IMMEDIATE:
--   SELECT serial → exists? 409 double-spend
--   else INSERT + UPDATE merchant.balance
-- token_hash = SHA256(serial‖R'‖s') is a belt-and-suspenders uniqueness
-- guard for the corner case where two different serials somehow yield the
-- same (R', s') tuple (shouldn't happen under correct protocol, but the
-- UNIQUE index on token_hash makes it a DB-level invariant).
CREATE TABLE IF NOT EXISTS spent_coins (
    serial         BLOB PRIMARY KEY,        -- 32-byte coin serial
    amount         INTEGER NOT NULL,
    deposited_to   INTEGER NOT NULL,         -- merchant user id
    token_hash     BLOB NOT NULL,           -- SHA256(serial‖R'‖s')
    spent_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (deposited_to) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sc_merchant ON spent_coins(deposited_to, spent_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sc_token_hash ON spent_coins(token_hash);
