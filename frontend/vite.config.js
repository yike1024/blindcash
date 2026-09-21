import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

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
  server: {
    // blindcash uses 5174 (cryptobank uses 5173) so both can run side-by-side.
    port: 5174,
    proxy: {
      '/api': {
        target: 'http://localhost:4100',
        changeOrigin: true,
      },
    },
  },
})
