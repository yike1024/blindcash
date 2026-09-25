import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.js'],
    globals: true,
    env: {
      // 统一注入测试用固定 BC_MASTER_KEY（64 hex chars = 32 bytes AES key），
      // 消除各测试进程报 "BC_MASTER_KEY not set — generated ephemeral key" 的警告。
      BC_MASTER_KEY: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    },
    // Run test files sequentially. All files share one PostgreSQL test DB
    // (DATABASE_URL); each file's beforeAll calls resetTestDb() to drop all
    // tables and re-run migrations for a clean slate. Parallel execution
    // would let test files trample each other's shared DB state.
    fileParallelism: false,
    // M2 introduces 1000-trial probabilistic tests (blindness-evidence entropy,
    // cheat-success rate over many cut-and-choose trials). Each trial does
    // ~50 secp256k1 scalar mults; default 5s timeout is too tight.
    testTimeout: 60000,
  },
});
