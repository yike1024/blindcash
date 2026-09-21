// crypto/client/blinding.js — α/β blinding factor generation + R' / s' compute
//
// v3 §2.3 + ISOLATION §6: the FRONT-END runs only this crypto/client/ subset.
// It uses Web Crypto API's crypto.getRandomValues (NOT Node's crypto.randomBytes,
// which is unavailable in the browser). vite-plugin-node-polyfills (installed
// in M1) provides Buffer/process shims so @noble/secp256k1 itself runs in the
// browser — but our RANDOM SOURCE is Web Crypto.
//
// Functions exported here MUST be safe to bundle by vite build (verified by
// tests/clientBuild.test.js).
//
// Security invariant (ISOLATION §3.3): α_j and β_j for the candidate that
// gets signed (index j, picked by the bank at submit) NEVER leave the user's
// device through any API. They are only used locally to compute R'_j and to
// unblind s_j → s'_j. After unblinding, they can be discarded.

import { Point } from '@noble/secp256k1';
import { G, n, modN, bytesToScalar, scalarToBytes } from '../server/curve.js';

/**
 * Generate two random blinders α, β ∈ [1, n-1] using Web Crypto.
 *
 * We draw 32 bytes from crypto.getRandomValues (the Web Crypto standard)
 * and reduce mod n-1 then +1, mapping to [1, n-1] (avoids the degenerate
 * 0 and n values).
 *
 * In a browser main thread, globalThis.crypto is the Web Crypto instance.
 * In Node 24 (used for tests), globalThis.crypto.webcrypto is polyfilled
 * natively. The vite-plugin-node-polyfills loaded in M1 ensures Buffer /
 * process shims don't break this path during `vite build`.
 *
 * @returns {{ alpha: bigint, beta: bigint, alphaBytes: Uint8Array, betaBytes: Uint8Array }}
 */
export function generateBlinders() {
  const alpha = randomScalarInRange();
  const beta = randomScalarInRange();
  return {
    alpha,
    beta,
    alphaBytes: scalarToBytes(alpha),
    betaBytes: scalarToBytes(beta),
  };
}

/**
 * Compute the blinded commitment R' = R + α·G + β·P.
 *
 * @param {Uint8Array} R          33-byte compressed bank commitment (R = k·G)
 * @param {bigint}     alpha      α (random blinder)
 * @param {bigint}     beta       β (random blinder)
 * @param {Uint8Array} publicKey  33-byte compressed bank public key P
 * @returns {Uint8Array} 33-byte compressed R'
 */
export function computeBlindedCommitment(R, alpha, beta, publicKey) {
  const Rp = Point.fromHex(bytesToHex(R));
  const P = Point.fromHex(bytesToHex(publicKey));
  const alphaG = G.multiply(alpha);
  const betaP = P.multiply(beta);
  const RPrime = Rp.add(alphaG).add(betaP);
  return RPrime.toRawBytes(true); // 33-byte compressed
}

/**
 * Unblind the bank's response: s' = (s + α) mod n.
 *
 * @param {bigint}     s      bank's response (from reveal step)
 * @param {bigint}     alpha   user's α for the signed candidate j
 * @returns {bigint}   s' = (s + α) mod n
 */
export function unblindResponse(s, alpha) {
  return modN(s + alpha);
}

// ── internal: random scalar in [1, n-1] using Web Crypto ──
function randomScalarInRange() {
  // Draw 32 bytes. The result might be ≥ n; rejection-sample by redrawing.
  // For secp256k1 n ≈ 2^256 - 2^128, so the rejection probability is ~2^-128.
  for (let attempt = 0; attempt < 64; attempt++) {
    const buf = new Uint8Array(32);
    globalThis.crypto.getRandomValues(buf);
    let s = bytesToScalar(buf);   // [0, 2^256-1]
    s = s % n;                    // [0, n-1]
    if (s >= 1n && s < n) return s;
  }
  // Astronomically unlikely (prob ≈ 2^-128). Fall back to a fresh draw mod
  // (n-1)+1, accepting a tiny bias (well below any practical attack bound).
  const buf = new Uint8Array(32);
  globalThis.crypto.getRandomValues(buf);
  let s = bytesToScalar(buf) % (n - 1n);
  s = s + 1n;
  return s;
}

// ── internal: bytesToHex (inlined to avoid a cross-module dependency on
//    utils/hex.js — this keeps the client bundle minimal)
function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

// re-export n/modN so the client doesn't need a separate import of curve.js
export { n, modN };
