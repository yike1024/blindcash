import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { nodePolyfills } from 'vite-plugin-node-polyfills'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // Polyfill Node core modules (Buffer, process, crypto, stream, etc.) so
    // that libraries like `elliptic` (used by crypto/client/ in M2/M6) work
    // in the browser. See v3 outline risk §一-1 (frontend crypto boundary).
    nodePolyfills({
      globals: { Buffer: true, global: true, process: true },
    }),
  ],
  resolve: {
    alias: {
      // M6: let front-end pages import backend's browser-safe crypto subset
      // (crypto/client/*, crypto/server/curve.js, crypto/server/hashToScalar.js,
      // utils/hex.js, config/bank.js) without relative paths crossing the
      // frontend/ boundary. All these modules were verified browser-runnable
      // by tests/clientBuild.test.js in M2 (vite build + happy-dom).
      '@crypto': resolve(__dirname, '../backend/src/crypto'),
      '@config': resolve(__dirname, '../backend/src/config'),
      '@utils': resolve(__dirname, '../backend/src/utils'),
    },
  },
  server: {
    // blindcash uses 5174 (cryptobank uses 5173) so both can run side-by-side.
    port: 5174,
    fs: {
      // Allow vite to serve/import files from backend/ (alias targets).
      allow: ['..'],
    },
    proxy: {
      '/api': {
        target: 'http://localhost:4100',
        changeOrigin: true,
      },
    },
  },
  // Phase 2: vitest config for frontend unit tests (walletDB, etc.).
  // happy-dom provides DOM APIs; fake-indexeddb is injected per-test-file
  // because happy-dom itself has no IndexedDB.
  test: {
    environment: 'happy-dom',
    globals: true,
    include: ['src/**/*.{test,spec}.{js,jsx}'],
  },
})
