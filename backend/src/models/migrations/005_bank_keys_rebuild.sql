-- 005_bank_keys_rebuild.sql — Phase 3 (PostgreSQL)
--
-- In the SQLite lineage this migration rebuilt bank_keys to support multi-key
-- rotation (key_version, status, retired_until). On PostgreSQL the baseline
-- already creates bank_keys with the full final schema, so this is a no-op.
SELECT 1;
