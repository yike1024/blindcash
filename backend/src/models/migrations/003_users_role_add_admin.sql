-- 003_users_role_add_admin.sql — Phase 1: 重建 users 表，role CHECK 含 admin
--
-- v5 §二 H3 (admin 角色种子方案) + §三 Phase 1 checklist 第 10 条：
--   users.role 原 CHECK(role IN ('customer','merchant')) 不含 admin，
--   SQLite 不能 ALTER TABLE 删 CHECK，必须重建表。
--
-- **P1 修正（v5 终审）**：重建表迁移必须 `PRAGMA foreign_keys=OFF` + 事务
-- 包裹 + `PRAGMA foreign_key_check` 验证。原因：schema.sql 里
-- withdrawal_sessions.customer_id / transactions.user_id / spent_coins
-- 等多张表都有 `FOREIGN KEY ... REFERENCES users(id)`，better-sqlite3
-- 默认 `PRAGMA foreign_keys=ON` 会让 DROP TABLE users 在有依赖时报错。
--
-- 标准重建模式（照抄进所有 future 重建表迁移）：
--   PRAGMA foreign_keys = OFF;
--   BEGIN;
--   CREATE TABLE users_new (...);
--   INSERT INTO users_new SELECT * FROM users;
--   DROP TABLE users;
--   ALTER TABLE users_new RENAME TO users;
--   COMMIT;
--   PRAGMA foreign_keys = ON;
--   PRAGMA foreign_key_check;  -- 应返回空集，否则重建破坏了 FK 完整性

PRAGMA foreign_keys = OFF;
BEGIN;
CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('customer','merchant','admin')),
    balance       INTEGER NOT NULL DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO users_new (id, username, password_hash, role, balance, created_at)
  SELECT id, username, password_hash, role, balance, created_at FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
COMMIT;
PRAGMA foreign_keys = ON;
PRAGMA foreign_key_check;  -- 应返回空集，否则说明重建破坏了 FK 完整性
