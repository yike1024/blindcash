// walletDB.test.js — Phase 2: IndexedDB wallet persistence tests
//
// v5 §三 Phase 2.1 验收：
//   ✓ 存入 token → IndexedDB 有记录
//   ✓ 关闭标签页重开 → token 仍在（fake-indexeddb 是内存实现，此处验证
//     putCoin → getCoin 同进程内持久化；真实浏览器 IndexedDB 跨会话持久）
//   ✓ 按 serial 删除 → 该 token 不再列出
//   ✓ clearAll → 钱包空
//   ✓ 重复 serial 存入 → ConstraintError（keyPath 防重）
//   ✓ 缺字段 → validateCoin 抛错（审查建议 5）
//
// 审查建议 2：happy-dom 无 IndexedDB，必须注入 fake-indexeddb/auto。
// 否则 indexedDB is not defined。

import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import {
  putCoin, getCoin, listCoins, deleteCoin, hasCoin, clearAll,
  totalBalance, _resetDbForTest,
} from '../utils/walletDB.js';

function makeCoin(overrides = {}) {
  return {
    serial: 'a'.repeat(64),
    amount: 30,
    R_prime: '02' + 'b'.repeat(64),
    s_prime: 'c'.repeat(64),
    key_id: 1,
    ...overrides,
  };
}

describe('walletDB — IndexedDB coin store', () => {
  beforeEach(async () => {
    _resetDbForTest();
    await clearAll();
  });

  it('putCoin persists a coin and getCoin retrieves it', async () => {
    const coin = makeCoin({ serial: '1'.repeat(64) });
    await putCoin(coin);
    const got = await getCoin(coin.serial);
    expect(got).toBeDefined();
    expect(got.serial).toBe(coin.serial);
    expect(got.amount).toBe(coin.amount);
    expect(got.R_prime).toBe(coin.R_prime);
    expect(got.s_prime).toBe(coin.s_prime);
    expect(got.key_id).toBe(1);
    expect(typeof got.created_at).toBe('number');
  });

  it('listCoins returns all coins sorted by created_at desc', async () => {
    const c1 = makeCoin({ serial: '1'.repeat(64), created_at: 1000 });
    const c2 = makeCoin({ serial: '2'.repeat(64), created_at: 2000 });
    const c3 = makeCoin({ serial: '3'.repeat(64), created_at: 1500 });
    await putCoin(c1);
    await putCoin(c2);
    await putCoin(c3);
    const list = await listCoins();
    expect(list).toHaveLength(3);
    // newest first: c2 (2000), c3 (1500), c1 (1000)
    expect(list[0].serial).toBe(c2.serial);
    expect(list[1].serial).toBe(c3.serial);
    expect(list[2].serial).toBe(c1.serial);
  });

  it('deleteCoin removes the coin by serial', async () => {
    const coin = makeCoin({ serial: '1'.repeat(64) });
    await putCoin(coin);
    expect(await hasCoin(coin.serial)).toBe(true);
    await deleteCoin(coin.serial);
    expect(await hasCoin(coin.serial)).toBe(false);
    expect(await getCoin(coin.serial)).toBeUndefined();
  });

  it('clearAll empties the wallet', async () => {
    await putCoin(makeCoin({ serial: '1'.repeat(64) }));
    await putCoin(makeCoin({ serial: '2'.repeat(64) }));
    expect(await listCoins()).toHaveLength(2);
    await clearAll();
    expect(await listCoins()).toHaveLength(0);
  });

  it('putCoin with duplicate serial throws (ConstraintError)', async () => {
    const coin = makeCoin({ serial: '1'.repeat(64) });
    await putCoin(coin);
    // keyPath='serial' → second add() with same key throws ConstraintError
    await expect(putCoin(coin)).rejects.toThrow();
  });

  it('putCoin rejects coin missing required fields', async () => {
    // missing s_prime
    await expect(putCoin({
      serial: 'a'.repeat(64),
      amount: 30,
      R_prime: '02' + 'b'.repeat(64),
    })).rejects.toThrow(/s_prime/);

    // non-integer amount
    await expect(putCoin({
      serial: 'a'.repeat(64),
      amount: 30.5,
      R_prime: '02' + 'b'.repeat(64),
      s_prime: 'c'.repeat(64),
    })).rejects.toThrow(/amount/);

    // wrong serial length
    await expect(putCoin({
      serial: 'short',
      amount: 30,
      R_prime: '02' + 'b'.repeat(64),
      s_prime: 'c'.repeat(64),
    })).rejects.toThrow(/serial/);
  });

  it('hasCoin returns true only for stored serials', async () => {
    const coin = makeCoin({ serial: '1'.repeat(64) });
    await putCoin(coin);
    expect(await hasCoin(coin.serial)).toBe(true);
    expect(await hasCoin('9'.repeat(64))).toBe(false);
  });

  it('totalBalance sums all coin amounts', async () => {
    await putCoin(makeCoin({ serial: '1'.repeat(64), amount: 30 }));
    await putCoin(makeCoin({ serial: '2'.repeat(64), amount: 70 }));
    expect(await totalBalance()).toBe(100);
  });
});
