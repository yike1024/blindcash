// tests/setup.js — shared test utilities (M2 crypto tests)
//
// No DB is touched by M2 tests (these are pure crypto unit tests, so the
// fileParallelism:false + shared PostgreSQL resetDb() isolation machinery
// from M1 is not invoked here). This file just exposes a couple of
// byte/hex/random helpers that the crypto test files reuse.
//
// We DELIBERATELY do NOT import from src/utils/hex.js — the tests need to
// be a faithful re-derivation of the encoding, not a tautological re-import
// of the code under test. If hex.js were buggy, tests using it would also
// be buggy.

export { bytesToHex, hexToBytes, randomBytes };

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd length ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Random bytes from Web Crypto. Works in Node 24 (webcrypto is global) and
 * in jsdom/happy-dom (the test environment for client-side tests).
 * @param {number} n
 * @returns {Uint8Array}
 */
function randomBytes(n) {
  const buf = new Uint8Array(n);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}
