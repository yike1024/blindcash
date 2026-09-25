-- 009_transactions_add_redeem_split_kind.sql — Phase 6.2 (PostgreSQL)
--
-- In the SQLite lineage this rebuilt the transactions table to extend the
-- kind CHECK constraint with 'redeem_split'. On PostgreSQL the baseline
-- already includes 'redeem_split' in the constraint, so this is a no-op.
SELECT 1;
