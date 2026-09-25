-- 007_bank_keys_add_denomination.sql — Phase 6.1 (PostgreSQL)
--
-- The denomination column already exists in the baseline bank_keys table.
-- This migration only creates the partial unique index ensuring at most one
-- active key per denomination.

CREATE UNIQUE INDEX IF NOT EXISTS idx_bk_active_denom
    ON bank_keys(denomination) WHERE status = 'active';
