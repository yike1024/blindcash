// tests/bankReserveService.test.js — Phase 1: bank_reserve 不变量断言
//
// v5 §三 1.1 M1 修正后的核心不变量（含在途项）：
//   reserve_balance == SUM(users.balance)
//                    + (total_issued − total_redeemed)
//                    + SUM(amount WHERE withdrawal_sessions.status
//                           IN ('pending','submitted'))
//
// 测试矩阵（5 cases, 见 plan 验收清单）：
//   ✓ Normal   — fundUser(deposit 100) 后不变量成立
//   ✓ Broken   — 直接 UPDATE users.balance 不更新 reserve → assertInvariant 抛错
//   ✓ Tx Rollback — runImmediateTx 内抛错 → 整个事务回滚，半状态不留
//   ✓ In-flight — pending withdrawal_session（amount=30）让 inFlight=30，
//                 不变量仍成立（init 已 debit balance，但 total_issued 还没加）
//   ✓ After reveal — reveal 成功后 session.status='committed'（不在 inFlight），
//                    total_issued += amount，不变量成立
//
// 关键：assertInvariant 必须在调用方事务内调用，失败时整个 BEGIN IMMEDIATE
// 回滚——本测试用 runImmediateTx 验证此语义。

import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  initSchema,
  getDb,
  closeDb,
  runImmediateTx,
  queryOne,
  runWrite,
} from '../src/models/db.js';
import {
  assertInvariant,
  ReserveInvariantError,
  ensureSingletonRow,
} from '../src/services/bankReserveService.js';
import { deposit } from '../src/services/bankService.js';
import { createUser } from '../src/services/userService.js';
import { fundUser, resetBalancesAndReserve } from './helpers/fundUser.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DB_PATH = join(__dirname, '..', 'data', 'test-p1-bankreserve.db');
process.env.BC_DB_PATH = TEST_DB_PATH;

initSchema();

let userId;

beforeAll(() => {
  // Clear any leftover data from previous runs (DB file may persist).
  const db = getDb();
  db.exec('DELETE FROM withdrawal_sessions;');
  db.exec('DELETE FROM spent_coins;');
  db.exec('DELETE FROM transactions;');
  db.exec('DELETE FROM users;');
  db.exec('DELETE FROM bank_keys;');
  db.exec('UPDATE bank_reserve SET total_issued=0, total_redeemed=0, reserve_balance=0 WHERE id=1;');

  // Create one user for all tests. Each beforeEach resets balances + reserve.
  const user = createUser('alice_reserve', 'hash', 'customer');
  userId = user.id;
});

beforeEach(() => {
  const db = getDb();
  resetBalancesAndReserve(db);
  // ensureSingletonRow is idempotent — defensive if reset cleared the row.
  ensureSingletonRow(db);
});

afterAll(() => {
  closeDb();
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(TEST_DB_PATH + suffix, { force: true }); } catch {}
  }
});

// ════════════════════════════════════════════════════════════════
// 1. NORMAL — invariant holds after a proper deposit
// ════════════════════════════════════════════════════════════════

describe('Phase 1 · bankReserveService — assertInvariant', () => {
  describe('Normal: invariant holds after a proper deposit', () => {
    it('fundUser(deposit 100) leaves the invariant in a consistent state', () => {
      // fundUser calls bankService.deposit, which atomically:
      //   users.balance += 100
      //   bank_reserve.reserve_balance += 100
      //   recordTransaction(kind='deposit')
      //   assertInvariant(db)  ← must pass
      fundUser(userId, 100);

      // Re-assert from outside any transaction — proves the committed state is consistent.
      const db = getDb();
      expect(() => assertInvariant(db)).not.toThrow();

      // Sanity: reserve_balance should equal 100 (sumBalance=100, issued=0,
      // redeemed=0, inFlight=0).
      const r = queryOne(
        'SELECT reserve_balance, total_issued, total_redeemed FROM bank_reserve WHERE id = 1',
      );
      expect(r.reserve_balance).toBe(100);
      expect(r.total_issued).toBe(0);
      expect(r.total_redeemed).toBe(0);
    });
  });

  // ════════════════════════════════════════════════════════════════
  // 2. BROKEN — direct UPDATE users.balance without reserve update breaks it
  // ════════════════════════════════════════════════════════════════

  describe('Broken: direct balance mutation without reserve update throws', () => {
    it('UPDATE users.balance += 50 without updating reserve → assertInvariant throws', () => {
      const db = getDb();
      // Mutate balance directly — bypasses bankService.deposit so
      // bank_reserve.reserve_balance is NOT updated. This simulates a bug
      // where some code path touches users.balance without going through the
      // service layer.
      runWrite(`UPDATE users SET balance = balance + ? WHERE id = ?`, [50, userId]);

      // sumBalance=50, reserve_balance=0, issued=0, redeemed=0, inFlight=0
      // expected = 50 + 0 + 0 = 50, but reserve_balance=0 → MISMATCH.
      expect(() => assertInvariant(db)).toThrow(ReserveInvariantError);

      // Verify the error carries the diagnostic details.
      let caught = null;
      try { assertInvariant(db); } catch (e) { caught = e; }
      expect(caught).not.toBeNull();
      expect(caught.details.reserve).toBe(0);
      expect(caught.details.expected).toBe(50);
      expect(caught.details.sumBalance).toBe(50);
    });

    it('also breaks when reserve is bumped but balance is not (off-by-direction bug)', () => {
      const db = getDb();
      // Opposite direction: bump reserve without bumping balance. Simulates
      // a bug where reserve is credited but the user account is missed.
      runWrite(`UPDATE bank_reserve SET reserve_balance = reserve_balance + 30 WHERE id = 1`);

      // sumBalance=0, reserve_balance=30, issued=0, redeemed=0, inFlight=0
      // expected = 0 + 0 + 0 = 0, but reserve_balance=30 → MISMATCH.
      expect(() => assertInvariant(db)).toThrow(ReserveInvariantError);
    });
  });

  // ════════════════════════════════════════════════════════════════
  // 3. TRANSACTION ROLLBACK — throw inside runImmediateTx rolls back whole tx
  // ════════════════════════════════════════════════════════════════

  describe('Tx Rollback: throw inside runImmediateTx reverts the whole tx', () => {
    it('a tx that mutates balance + reserve then throws leaves no half-state', () => {
      const db = getDb();
      // Snapshot pre-state.
      const before = queryOne(
        'SELECT reserve_balance, total_issued, total_redeemed FROM bank_reserve WHERE id = 1',
      );
      const userBefore = queryOne('SELECT balance FROM users WHERE id = ?', [userId]);

      // Run a tx that does the "right" mutations then throws — simulating
      // a code path where assertInvariant (or any later step) fails after
      // the balance + reserve updates have already been issued.
      expect(() =>
        runImmediateTx((tx) => {
          tx.prepare(`UPDATE users SET balance = balance + ? WHERE id = ?`)
            .run(200, userId);
          tx.prepare(`UPDATE bank_reserve SET reserve_balance = reserve_balance + ? WHERE id = 1`)
            .run(200);
          // Throw BEFORE assertInvariant — emulate a later-step failure.
          throw new Error('synthetic failure after balance + reserve mutation');
        }),
      ).toThrow();

      // Post-state MUST equal pre-state — the whole tx rolled back.
      const after = queryOne(
        'SELECT reserve_balance, total_issued, total_redeemed FROM bank_reserve WHERE id = 1',
      );
      const userAfter = queryOne('SELECT balance FROM users WHERE id = ?', [userId]);
      expect(after.reserve_balance).toBe(before.reserve_balance);
      expect(userAfter.balance).toBe(userBefore.balance);
    });

    it('assertInvariant failure inside runImmediateTx rolls back the tx (no half-state)', () => {
      const db = getDb();
      // This is the actual production pattern: deposit updates balance + reserve
      // + recordTransaction + assertInvariant. If assertInvariant throws, the
      // whole BEGIN IMMEDIATE rolls back.
      //
      // We simulate this by deliberately breaking the invariant mid-tx:
      //   1. UPDATE users.balance += 100 (correct)
      //   2. UPDATE bank_reserve.reserve_balance += 50  (WRONG — should be 100)
      //   3. assertInvariant(db)  ← throws
      // The whole tx rolls back → users.balance unchanged, reserve unchanged.
      const before = queryOne('SELECT balance FROM users WHERE id = ?', [userId]);
      const rBefore = queryOne(
        'SELECT reserve_balance FROM bank_reserve WHERE id = 1',
      );

      expect(() =>
        runImmediateTx((tx) => {
          tx.prepare(`UPDATE users SET balance = balance + ? WHERE id = ?`)
            .run(100, userId);
          // Wrong amount — should be 100 to match the user balance bump.
          tx.prepare(`UPDATE bank_reserve SET reserve_balance = reserve_balance + ? WHERE id = 1`)
            .run(50);
          // This MUST throw because expected (100) != reserve_balance (50).
          assertInvariant(tx);
        }),
      ).toThrow(ReserveInvariantError);

      const after = queryOne('SELECT balance FROM users WHERE id = ?', [userId]);
      const rAfter = queryOne(
        'SELECT reserve_balance FROM bank_reserve WHERE id = 1',
      );
      expect(after.balance).toBe(before.balance);
      expect(rAfter.reserve_balance).toBe(rBefore.reserve_balance);
    });
  });

  // ════════════════════════════════════════════════════════════════
  // 4. IN-FLIGHT — pending withdrawal_session contributes to inFlight
  // ════════════════════════════════════════════════════════════════

  describe('In-flight: pending withdrawal_session contributes to inFlight term', () => {
    it('a pending session with amount=30 makes inFlight=30, invariant holds', () => {
      const db = getDb();
      // Fund user 100 (proper deposit — reserve_balance=100, sumBalance=100).
      fundUser(userId, 100);

      // Simulate the post-init state of a withdrawal: the customer called
      // /api/withdraw/init with amount=30. withdrawalService does:
      //   users.balance -= 30          (locked for withdrawal)
      //   bank_reserve.reserve_balance -= 30  (in-flight is not "free money")
      //   INSERT withdrawal_sessions (status='pending', amount=30)
      //   assertInvariant(db)
      //
      // After init: sumBalance=70, reserve_balance=70, inFlight=30,
      // expected = 70 + (0-0) + 30 = 100... wait, that's wrong. Let me
      // re-derive: actually the invariant holds because reserve_balance was
      // decremented along with balance — the user's 30 locked BC moved from
      // "balance" to "in-flight". So:
      //   reserve_balance=70 (was 100, -30 to mirror the locked balance)
      //   sumBalance=70 (was 100, -30 locked)
      //   inFlight=30
      //   expected = 70 + 0 + 30 = 100... but reserve_balance=70, not 100.
      //
      // Hmm — that suggests reserve_balance should NOT be decremented at
      // init. Let me re-read the invariant:
      //   reserve_balance == SUM(balance) + (issued - redeemed) + inFlight
      // The "inFlight" term is ADDED — so if reserve_balance stayed at 100
      // and balance went 100→70 with inFlight=30, then 100 == 70 + 0 + 30 ✓.
      // That's the correct interpretation: reserve_balance stays constant
      // during init; the locked amount moves from "balance" to "inFlight".
      //
      // So: simulate init by:
      //   users.balance -= 30
      //   INSERT withdrawal_sessions(status='pending', amount=30)
      //   (reserve_balance UNCHANGED)
      //   assertInvariant(db)  ← must pass
      runImmediateTx((tx) => {
        tx.prepare(`UPDATE users SET balance = balance - ? WHERE id = ?`)
          .run(30, userId);
        tx.prepare(
          `INSERT INTO withdrawal_sessions
             (id, customer_id, amount, n_candidates, candidates, expires_at, status)
           VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
        ).run(
          'test-session-1',
          userId,
          30,
          4,
          '[]',
          new Date(Date.now() + 5 * 60 * 1000).toISOString()
            .replace('T', ' ')
            .replace('Z', ''),
        );
        // Invariant must hold: 100 == 70 + 0 + 30.
        assertInvariant(tx);
      });

      // Confirm the inFlight term is actually 30 (proves the SELECT in
      // assertInvariant picked up the pending session).
      const inFlight = queryOne(
        `SELECT COALESCE(SUM(amount), 0) AS s FROM withdrawal_sessions
          WHERE status IN ('pending','submitted')`,
      ).s;
      expect(inFlight).toBe(30);

      // And re-assert from outside the tx.
      expect(() => assertInvariant(db)).not.toThrow();
    });

    it('moving session to "committed" removes the inFlight term but total_issued += amount', () => {
      const db = getDb();
      // Fund 100, simulate init (balance→70, inFlight=30, reserve=100).
      fundUser(userId, 100);
      runImmediateTx((tx) => {
        tx.prepare(`UPDATE users SET balance = balance - ? WHERE id = ?`)
          .run(30, userId);
        tx.prepare(
          `INSERT INTO withdrawal_sessions
             (id, customer_id, amount, n_candidates, candidates, expires_at, status)
           VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
        ).run(
          'test-session-2',
          userId,
          30,
          4,
          '[]',
          new Date(Date.now() + 5 * 60 * 1000).toISOString()
            .replace('T', ' ')
            .replace('Z', ''),
        );
        assertInvariant(tx);
      });

      // Now simulate the post-reveal state: session.status='committed'
      // (no longer in inFlight), total_issued += 30 (signed token minted).
      // bank_reserve.reserve_balance UNCHANGED (still 100).
      // New expected: 100 == 70 (balance) + (30 issued - 0 redeemed) + 0 (inFlight) ✓
      runImmediateTx((tx) => {
        tx.prepare(
          `UPDATE withdrawal_sessions SET status = 'committed' WHERE id = ?`,
        ).run('test-session-2');
        tx.prepare(
          `UPDATE bank_reserve SET total_issued = total_issued + ? WHERE id = 1`,
        ).run(30);
        assertInvariant(tx);
      });

      // Confirm: total_issued=30, inFlight=0, reserve_balance=100, sumBalance=70.
      const r = queryOne(
        'SELECT reserve_balance, total_issued, total_redeemed FROM bank_reserve WHERE id = 1',
      );
      expect(r.total_issued).toBe(30);
      expect(r.total_redeemed).toBe(0);
      expect(r.reserve_balance).toBe(100);
      const inFlight = queryOne(
        `SELECT COALESCE(SUM(amount), 0) AS s FROM withdrawal_sessions
          WHERE status IN ('pending','submitted')`,
      ).s;
      expect(inFlight).toBe(0);
      expect(() => assertInvariant(db)).not.toThrow();
    });
  });
});
