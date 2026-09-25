-- 001_init_baseline.sql — Phase 0: initial schema baseline (PostgreSQL)
--
-- Converted from SQLite:
--   INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
--   BLOB  → BYTEA
--   DATETIME → TIMESTAMP
--   PRAGMA statements removed (PG enforces FKs by default; WAL is built-in)
--   CHECK constraints are explicitly named so later migrations can DROP/ALTER them.

-- ── 身份层：用户 ──
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CONSTRAINT users_role_check
                  CHECK(role IN ('customer','merchant','admin')),
    balance       INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── 密钥层：银行签名密钥 ──
-- ⚠ private_key is AES-256-GCM encrypted at rest (ISOLATION §五 不变量 7).
CREATE TABLE IF NOT EXISTS bank_keys (
    id            SERIAL PRIMARY KEY,
    key_version   INTEGER UNIQUE NOT NULL,
    denomination  INTEGER NOT NULL DEFAULT 1,
    public_key    BYTEA NOT NULL,
    private_key   BYTEA NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK(status IN ('active','retired')),
    retired_until TIMESTAMP,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    retired_at    TIMESTAMP
);

-- ── 取款层：4-move 协议会话状态机 ──
CREATE TABLE IF NOT EXISTS withdrawal_sessions (
    id            TEXT PRIMARY KEY,
    customer_id   INTEGER NOT NULL,
    amount        INTEGER NOT NULL,
    denomination  INTEGER NOT NULL DEFAULT 1,
    n_candidates  INTEGER NOT NULL,
    candidates    TEXT NOT NULL,
    j_index       INTEGER,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','submitted','committed','aborted','cancelled','expired')),
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP NOT NULL,
    FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ws_customer ON withdrawal_sessions(customer_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ws_active_per_customer
    ON withdrawal_sessions(customer_id) WHERE status IN ('pending','submitted');

-- ── 双花检测层：已花费 token ──
CREATE TABLE IF NOT EXISTS spent_coins (
    id            SERIAL PRIMARY KEY,
    serial        BYTEA NOT NULL UNIQUE,
    amount        INTEGER NOT NULL,
    deposited_to  INTEGER NOT NULL,
    token_hash    BYTEA NOT NULL,
    key_version   INTEGER,
    denomination  INTEGER NOT NULL DEFAULT 1,
    spent_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (deposited_to) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sc_merchant ON spent_coins(deposited_to, spent_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sc_token_hash ON spent_coins(token_hash);

-- ── 账本层：交易流水 ──
CREATE TABLE IF NOT EXISTS transactions (
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER NOT NULL,
    kind          TEXT NOT NULL CONSTRAINT transactions_kind_check
                  CHECK(kind IN ('withdraw','deposit','refund','redeem_split')),
    amount        INTEGER NOT NULL,
    counterparty  TEXT,
    serial        BYTEA,
    session_id    TEXT,
    note          TEXT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tx_user_time ON transactions(user_id, created_at DESC);
