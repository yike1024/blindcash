-- 003_users_role_add_admin.sql — Phase 1 (PostgreSQL)
--
-- In the SQLite lineage this migration rebuilt the users table to extend the
-- role CHECK constraint to include 'admin'. On PostgreSQL the baseline
-- (001_init_baseline.sql) already creates users.role with
-- CHECK(role IN ('customer','merchant','admin')), so this migration is a
-- no-op. Kept for version-bookkeeping continuity.
SELECT 1;
