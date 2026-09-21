import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.js'],
    globals: true,
    // Run test files sequentially. Each file sets its own BC_DB_PATH and the
    // db.js singleton (_db) is per-process — parallel execution would let
    // test files trample each other's DB connection. Sequential + afterEach
    // closeDb() ensures each file opens its own isolated test DB.
    fileParallelism: false,
    // M2 introduces 1000-trial probabilistic tests (blindness-evidence entropy,
    // cheat-success rate over many cut-and-choose trials). Each trial does
    // ~50 secp256k1 scalar mults; default 5s timeout is too tight.
    testTimeout: 60000,
  },
});
