-- schema_migrations.sql — Phase 0: migration bookkeeping table
--
-- Tracks which migration versions have been applied to this DB.
-- migrationRunner.js reads this to know where to resume on next boot.
--
-- v5 §二 H1 design:
--   version     — sequential integer version number (001, 002, ...)
--   name        — migration name (e.g. "001_init_baseline", derived from filename)
--   applied_at  — when this migration was applied (CURRENT_TIMESTAMP)
--
-- The (version, name) pair is informational — version is the canonical key.
-- Migration files live in models/migrations/ and are applied in filename sort
-- order (which matches version-number order when zero-padded).
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,           -- 顺序整数版本号
    name        TEXT NOT NULL,                 -- 迁移名（如 "001_init_baseline"）
    applied_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
