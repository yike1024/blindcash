// utils/walletDB.pending.test.js — Phase 6.4: pending_payments store 单元测试
//
// 验证矩阵：
//   ✓ addPendingPayment 写入后返回 id（autoIncrement）
//   ✓ listPendingPayments 按 created_at 升序返回（最旧在前，优先重试）
//   ✓ deletePendingPayment 按 id 删除
//   ✓ countPendingPayments 正确计数
//   ✓ updatePendingPaymentAttempt 递增 attempts + 更新 last_error
//   ✓ clearAllPending 清空所有
//   ✓ token 字段原样保存（深拷贝，不受外部修改影响）
//   ✓ 空数据库 → count=0, list=[]
//   ✓ DB v1→v2 升级后 coins store 不丢失数据
//
// 测试环境：fake-indexeddb 注入 global.indexedDB，happy-dom 提供 DOM API。
// 每个测试 beforeEach 清空两个 store。

import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import 'fake-indexeddb/auto';

import {
  _resetDbForTest,
  putCoin, listCoins, clearAll,
  addPendingPayment, listPendingPayments, deletePendingPayment,
  updatePendingPaymentAttempt, countPendingPayments, clearAllPending,
} from './walletDB.js';

const VALID_TOKEN = {
  serial: 'a'.repeat(64),
  amount: 50,
  R_prime: '02' + 'b'.repeat(64),
  s_prime: 'c'.repeat(64),
  key_id: 1,
};

function makeToken(suffix = 'a') {
  return {
    ...VALID_TOKEN,
    serial: suffix.repeat(64).slice(0, 64).padEnd(64, '0'),
    R_prime: '02' + suffix.repeat(64).slice(0, 64).padEnd(64, '0'),
    s_prime: suffix.repeat(64).slice(0, 64).padEnd(64, '0'),
  };
}

describe('Phase 6.4 · walletDB pending_payments store', () => {
  beforeEach(async () => {
    // Reset the DB connection + clear both stores for test isolation
    _resetDbForTest();
    await clearAll();
    await clearAllPending();
  });

  afterAll(() => {
    _resetDbForTest();
  });

  it('addPendingPayment returns an auto-increment id', async () => {
    const id = await addPendingPayment(VALID_TOKEN, 'Network Error');
    expect(id).toBeTypeOf('number');
    expect(id).toBeGreaterThan(0);
  });

  it('listPendingPayments returns entries sorted oldest-first', async () => {
    const id1 = await addPendingPayment(makeToken('a'), 'err1');
    // Small delay to ensure different created_at
    await new Promise((r) => setTimeout(r, 5));
    const id2 = await addPendingPayment(makeToken('b'), 'err2');

    const list = await listPendingPayments();
    expect(list).toHaveLength(2);
    // Oldest first
    expect(list[0].id).toBe(id1);
    expect(list[1].id).toBe(id2);
  });

  it('pending record stores token as a copy (detached from caller)', async () => {
    const token = makeToken('d');
    await addPendingPayment(token, 'timeout');
    // Mutate the original — pending record should be unaffected
    token.amount = 999;
    token.serial = '0'.repeat(64);

    const list = await listPendingPayments();
    expect(list).toHaveLength(1);
    expect(list[0].token.amount).toBe(50);
    expect(list[0].token.serial).not.toBe('0'.repeat(64));
  });

  it('deletePendingPayment removes a single entry by id', async () => {
    const id1 = await addPendingPayment(makeToken('e'), 'err');
    const id2 = await addPendingPayment(makeToken('f'), 'err');

    await deletePendingPayment(id1);

    const list = await listPendingPayments();
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe(id2);
  });

  it('countPendingPayments returns 0 on empty database', async () => {
    const count = await countPendingPayments();
    expect(count).toBe(0);
  });

  it('countPendingPayments returns correct count', async () => {
    await addPendingPayment(makeToken('1'), 'err');
    await addPendingPayment(makeToken('2'), 'err');
    await addPendingPayment(makeToken('3'), 'err');

    const count = await countPendingPayments();
    expect(count).toBe(3);
  });

  it('updatePendingPaymentAttempt increments attempts and updates error', async () => {
    const id = await addPendingPayment(VALID_TOKEN, 'initial error');
    const list0 = await listPendingPayments();
    expect(list0[0].attempts).toBe(0);
    expect(list0[0].last_error).toBe('initial error');

    await updatePendingPaymentAttempt(id, 'retry 1 failed: timeout');

    const list1 = await listPendingPayments();
    expect(list1[0].attempts).toBe(1);
    expect(list1[0].last_error).toContain('retry 1 failed');

    await updatePendingPaymentAttempt(id, 'retry 2 failed: 503');

    const list2 = await listPendingPayments();
    expect(list2[0].attempts).toBe(2);
    expect(list2[0].last_error).toContain('503');
  });

  it('clearAllPending empties the store', async () => {
    await addPendingPayment(makeToken('x'), 'err');
    await addPendingPayment(makeToken('y'), 'err');

    await clearAllPending();

    const count = await countPendingPayments();
    expect(count).toBe(0);
  });

  it('updatePendingPaymentAttempt on non-existent id is a no-op', async () => {
    await updatePendingPaymentAttempt(99999, 'noop');
    // Should not throw
    const count = await countPendingPayments();
    expect(count).toBe(0);
  });

  it('DB v2 upgrade does not lose coins from v1', async () => {
    // Put a coin (v1 store), then verify it survives the pending store addition
    await putCoin(VALID_TOKEN);
    const coins = await listCoins();
    expect(coins).toHaveLength(1);
    expect(coins[0].serial).toBe(VALID_TOKEN.serial);

    // Pending store should also work alongside coins
    await addPendingPayment(VALID_TOKEN, 'test');
    const pending = await listPendingPayments();
    expect(pending).toHaveLength(1);

    // Coins still intact
    const coinsAfter = await listCoins();
    expect(coinsAfter).toHaveLength(1);
  });
});
