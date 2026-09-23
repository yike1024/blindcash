// config/bank.js — bank-side protocol constants
//
// v3 §2.3: cut-and-choose default N=100 (1% cheat probability).
// For live demos you can lower this to 10 to make the 4-move flow finish
// faster — but the outline requires documentation to explicitly mark this as
// "demo only; production uses N=100".
//
// v3 §2.1: domain separation tag for H("blindcash-v1" ‖ data). This tag is
// mixed into the hash-to-scalar function (crypto/server/hashToScalar.js)
// so the same (R', serial, amount) tuple cannot be replayed against a
// different protocol/chain.

/**
 * Cut-and-choose candidate count. N=100 → 1% cheat probability.
 * Override to 10 ONLY for demo runs (set BC_DEMO_N=10 in env).
 */
export const CUT_AND_CHOOSE_N = Number(process.env.BC_DEMO_N) || 100;

/**
 * Withdrawal session TTL in milliseconds. After this, a pending/submitted
 * session is eligible for lazy-cleanup refund on the user's next init/submit.
 * Default: 5 minutes — long enough for a demo, short enough to bound the
 * "abandoned but balance held" window.
 */
export const SESSION_TTL_MS = Number(process.env.BC_SESSION_TTL_MS) || 5 * 60 * 1000;

/**
 * Domain separation tag for the blind-signing hash. Mixed into H(tag ‖ data)
 * to prevent cross-protocol signature reuse.
 *
 * NOTE: changing this tag invalidates every previously-issued token.
 *
 * M6 修复：定义下沉到 crypto/client/protocolConstants.js（前端密码学子集可
 * 安全引用，无 Node 依赖）。本文件 import 后 re-export，保持后端 API 不变。
 */
import { TOKEN_DOMAIN_TAG } from '../crypto/client/protocolConstants.js';
export { TOKEN_DOMAIN_TAG };

/**
 * Bank keys singleton row id. The bank_keys table is constrained by
 * CHECK(id = 1) — there is exactly one signing keypair per bank.
 *
 * Phase 3 (v5 §三 3.2)：bank_keys 重建为多行表（005 迁移去掉 CHECK），
 * 此常量保留用于旧代码 backward-compat 引用，但新代码应通过 key_version
 * 而非 id 定位密钥。
 */
export const BANK_KEY_ROW_ID = 1;

/**
 * Master encryption key for at-rest encryption of bank private keys.
 *
 * Phase 3 (v5 §三 3.1)：私钥用 AES-256-GCM 加密后存 DB。
 *   格式：32-byte hex 字符串（64 hex chars），不是 passphrase→KDF。
 *   从环境变量 BC_MASTER_KEY 读，启动时校验格式。
 *   测试/开发环境：未设 BC_MASTER_KEY 时生成 ephemeral key（进程内随机，
 *     不持久化），日志 warn。每次进程重启 key 不同，但测试 beforeEach
 *     清空 bank_keys 表所以不影响。
 *
 * ⚠ at-rest encryption 只防 DB 文件泄露，不防服务器进程被控
 *   （运行时密钥必然在内存明文）。真实 HSM 是签名不出设备，本系统
 *   未实现 HSM（见 docs/DESIGN.md §10）。
 */
import { randomBytes } from 'node:crypto';
import { logger } from '../utils/logger.js';

const _rawMasterKey = process.env.BC_MASTER_KEY;
let MASTER_KEY;

if (_rawMasterKey) {
  // Validate: 32-byte hex = 64 hex chars
  if (!/^[0-9a-fA-F]{64}$/.test(_rawMasterKey)) {
    throw new Error(
      'BC_MASTER_KEY must be a 32-byte hex string (64 hex chars), e.g. ' +
      'a1b2c3... (64 chars). Got length ' + _rawMasterKey.length,
    );
  }
  MASTER_KEY = _rawMasterKey.toLowerCase();
} else {
  // Test/dev: generate ephemeral key (not persisted across restarts)
  MASTER_KEY = randomBytes(32).toString('hex');
  logger.warn({
    msg: 'BC_MASTER_KEY not set — generated ephemeral key (not safe for production)',
  });
}

export { MASTER_KEY };
