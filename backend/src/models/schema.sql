-- BlindCash 最终 schema 参考（PostgreSQL）— Phase 1-6 汇总
--
-- 该文件是"最终态" DDL 快照，供阅读与文档引用使用；
-- 真实建表顺序见 src/models/migrations/001_init_baseline.sql ~ 009_*.sql，
-- 由 src/utils/migrationRunner.js 幂等执行（schema_migrations 表记录版本）。
--
-- 与早期 SQLite lineage 的对应关系：
--   INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
--   BLOB  → BYTEA
--   DATETIME → TIMESTAMP
--   PRAGMA 删除（PG 默认强制 FK；WAL 内建）
--   CHECK 约束显式命名，便于后续迁移 DROP/ALTER

-- ── 身份层：用户（假名 + 密码 + 角色 + 法币余额） ──
-- role ∈ ('customer','merchant','admin')，互斥；
-- balance 为最小单位整数，由 bankService.deposit / withdrawalService 增减。
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,           -- pseudonym, NOT real name
    password_hash TEXT NOT NULL,                  -- bcrypt hash (rounds=12)
    role          TEXT NOT NULL CONSTRAINT users_role_check
                  CHECK(role IN ('customer','merchant','admin')),
    balance       INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── 密钥层：银行签名密钥（多 key_version / denomination） ──
-- ⚠ private_key 以 AES-256-GCM 加密落库（BC_MASTER_KEY 派生 key，
--   见 bankKeyService.js encryptPrivateKey / decryptPrivateKey）。
-- key_version 全局单调递增（MAX(key_version)+1，写入侧由
--   pg_advisory_xact_lock 串行化防止并发 race）。
-- 每个 denomination 至多一条 status='active' 行（idx_bk_active_denom）。
CREATE TABLE IF NOT EXISTS bank_keys (
    id            SERIAL PRIMARY KEY,
    key_version   INTEGER UNIQUE NOT NULL,
    denomination  INTEGER NOT NULL DEFAULT 1,
    public_key    BYTEA NOT NULL,                 -- 33-byte compressed P = xG
    private_key   BYTEA NOT NULL,                 -- AES-256-GCM(32B x) → 60B ciphertext
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK(status IN ('active','retired')),
    retired_until TIMESTAMP,                      -- 过期宽限（Phase 3 密钥轮转）
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    retired_at    TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_bk_active_denom
    ON bank_keys(denomination) WHERE status = 'active';

-- ── 取款层：4-move 协议会话状态机 ──
-- status: pending → submitted → committed | aborted | cancelled | expired
-- 同一 customer 至多一条 active session（idx_ws_active_per_customer 兜底）。
CREATE TABLE IF NOT EXISTS withdrawal_sessions (
    id            TEXT PRIMARY KEY,               -- UUIDv4 (crypto.randomUUID)
    customer_id   INTEGER NOT NULL,
    amount        INTEGER NOT NULL,
    denomination  INTEGER NOT NULL DEFAULT 1,     -- Phase 6 多面值
    n_candidates  INTEGER NOT NULL,               -- CUT_AND_CHOOSE_N at init
    candidates    TEXT NOT NULL,                  -- JSON array (无 α_i/β_i，ISOLATION §三-3)
    j_index       INTEGER,                        -- bank-picked j (set at submit)
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK(status IN ('pending','submitted','committed',
                                   'aborted','cancelled','expired')),
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMP NOT NULL,             -- created_at + SESSION_TTL_MS
    FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ws_customer ON withdrawal_sessions(customer_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ws_active_per_customer
    ON withdrawal_sessions(customer_id) WHERE status IN ('pending','submitted');

-- ── 双花检测层：已花费 token ──
-- serial UNIQUE 是主防双花约束；token_hash = SHA256(serial‖R'‖s') 作为
-- belt-and-suspenders 第二层。并发 INSERT 撞 serial → SQLSTATE 23505 → 409。
CREATE TABLE IF NOT EXISTS spent_coins (
    id            SERIAL PRIMARY KEY,
    serial        BYTEA NOT NULL UNIQUE,          -- 32-byte coin serial
    amount        INTEGER NOT NULL,
    deposited_to  INTEGER NOT NULL,               -- merchant user id
    token_hash    BYTEA NOT NULL,                 -- SHA256(serial‖R'‖s')
    key_version   INTEGER,                        -- 兑付时的 bank key_version
    denomination  INTEGER NOT NULL DEFAULT 1,     -- Phase 6
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
    amount        INTEGER NOT NULL,               -- 正整数；方向由 kind 决定
    counterparty  TEXT,                           -- 'bank' / NULL（deposit 匿名）
    serial        BYTEA,                          -- 32B coin serial（仅 deposit/redeem_split）
    session_id    TEXT,                           -- withdrawal session id（仅 withdraw/refund）
    note          TEXT,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tx_user_time ON transactions(user_id, created_at DESC);

-- ── 储备层：银行准备金 singleton（Phase 1） ──
-- 不变量（v5 §三 1.1，含在途项）：
--   reserve_balance == SUM(users.balance)
--                    + (total_issued − total_redeemed)
--                    + SUM(amount WHERE withdrawal_sessions.status
--                           IN ('pending','submitted'))
-- 由 bankReserveService.assertInvariant 在调用方事务末尾断言；
-- 失败抛 ReserveInvariantError → 事务回滚。
CREATE TABLE IF NOT EXISTS bank_reserve (
    id              INTEGER PRIMARY KEY CHECK(id = 1),
    total_issued    INTEGER NOT NULL DEFAULT 0,
    total_redeemed  INTEGER NOT NULL DEFAULT 0,
    reserve_balance INTEGER NOT NULL DEFAULT 0,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO bank_reserve (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- ── 审计层：操作日志（Phase 3） ──
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    actor_id    INTEGER,
    action      TEXT NOT NULL,
    target      TEXT,
    amount      INTEGER,
    meta        TEXT,
    ip_address  TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_log(action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor_time  ON audit_log(actor_id, created_at DESC);

-- ── 托管层：在线收款单与两阶段托管（Phase 7） ──
CREATE TABLE IF NOT EXISTS payment_escrows (
    id            TEXT PRIMARY KEY,
    merchant_id   INTEGER NOT NULL,
    customer_id   INTEGER,
    amount        INTEGER NOT NULL CHECK(amount > 0),
    denomination  INTEGER NOT NULL DEFAULT 1,
    challenge     TEXT NOT NULL UNIQUE,
    serial        BYTEA UNIQUE,
    token_hash    BYTEA,
    status        TEXT NOT NULL DEFAULT 'created'
                  CHECK(status IN ('created','locked','committed','cancelled','expired')),
    expires_at    TIMESTAMP NOT NULL,
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

-- ── 迁移版本表（migrationRunner 内部使用） ──
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    applied_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
