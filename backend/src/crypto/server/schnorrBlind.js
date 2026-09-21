// crypto/server/schnorrBlind.js — Schnorr blind signature (bank side, 4-move)
//
// v3 §2.2 (single-candidate math) + §2.3 (cut-and-choose 4-move):
//
//   Setup: bank generates x ∈ [1, n-1] random; P = x·G  (stored in bank_keys)
//
//   ① bankStep1(k)         → R = k·G            (bank → user, commitment)
//   ② user (client)        → R' = R + α·G + β·P; e' = H(tag‖R'‖serial‖amount‖P)
//                              e = (e' + β) mod n
//   ③ bankStep3(k, e, x)   → s = (k + e·x) mod n (bank → user, response)
//   ④ user (client)        → s' = (s + α) mod n (unblind)
//                              token = (serial, amount, R', s')
//
//   verify(R', s', serial, amount, P): s'·G ?= R' + e'·P
//     where e' = H(tag‖R'‖serial‖amount‖P) mod n
//
// Correctness proof (v3 §2.2):
//   s'·G = (s + α)·G = (k + e·x + α)·G = R + α·G + e·x·G
//        = R + α·G + (e' + β)·x·G    [substitute e = e' + β]
//        = R + α·G + β·P + e'·P
//        = (R + α·G + β·P) + e'·P = R' + e'·P  ✓
//
// This module is the BANK side — only step1, step3, verify, and keypair
// generation. The user side (blinding, unblind, computeChallenge) lives in
// crypto/client/blinding.js + schnorrBlindClient.js so the same code path
// can run in the browser via vite build.

import {
  G,
  n,
  modN,
  scalarToBytes,
  bytesToScalar,
  encodePoint,
  decodePoint,
  randomScalar,
  isValidScalar,
} from './curve.js';
import { hashToScalar } from './hashToScalar.js';
import { TOKEN_DOMAIN_TAG } from '../../config/bank.js';

/**
 * Generate a fresh bank keypair.
 * @returns {{ x: bigint, P: Point, publicKey: Uint8Array, privateKey: Uint8Array }}
 */
export function generateKeyPair() {
  const x = randomScalar();
  // defensive: utils.randomPrivateKey() already guarantees [1, n-1]
  if (!isValidScalar(x)) throw new Error('generated scalar out of range');
  const P = G.multiply(x);
  return {
    x,
    P,
    publicKey: encodePoint(P),       // 33-byte compressed
    privateKey: scalarToBytes(x),    // 32-byte big-endian
  };
}

/**
 * ① Bank step 1: produce the per-candidate commitment R = k·G.
 *
 * @param {bigint} k  per-candidate random nonce (must be fresh per session,
 *                    never reused across sessions — see ISOLATION.md §5)
 * @returns {{ R: Point, RBytes: Uint8Array }} R as a Point + 33-byte encoding
 */
export function bankStep1(k) {
  if (!isValidScalar(k)) throw new Error('bankStep1: k out of range [1, n-1]');
  const R = G.multiply(k);
  return { R, RBytes: encodePoint(R) };
}

/**
 * ③ Bank step 3: respond to the blinded challenge e with s = (k + e·x) mod n.
 *
 * The bank only ever sees the BLINDED e (e' + β mod n), so it cannot learn
 * e' or β. This is the core of the blind signature property.
 *
 * @param {bigint} k  per-candidate nonce (same as bankStep1)
 * @param {bigint} e  blinded challenge (e' + β) mod n
 * @param {bigint} x  bank private key
 * @returns {bigint}  s = (k + e·x) mod n
 */
export function bankStep3(k, e, x) {
  // s = k + e·x mod n  (Schnorr linear response)
  return modN(k + modN(e * x));
}

/**
 * Verify a final (unblinded) token signature.
 *
 *   e' = H(tag ‖ R' ‖ serial ‖ amount ‖ P) mod n
 *   accept iff s'·G == R' + e'·P
 *
 * @param {Uint8Array} RPrime    33-byte compressed R' (token component)
 * @param {bigint|Uint8Array} sPrime  s' (unblinded response), bigint or 32-byte BE
 * @param {Uint8Array} serial    32-byte coin serial
 * @param {number}     amount    positive integer
 * @param {Uint8Array} publicKey 33-byte compressed bank public key P
 * @returns {boolean}
 */
export function verifySig(RPrime, sPrime, serial, amount, publicKey) {
  try {
    const s = typeof sPrime === 'bigint' ? sPrime : bytesToScalar(sPrime);
    if (!isValidScalar(s)) return false;       // s must be in [1, n-1]
    if (s === 0n) return false;                 // s = 0 trivially fails verify eq.

    const Rp = decodePoint(RPrime);             // throws if R' not on curve
    const P = decodePoint(publicKey);           // throws if P not on curve

    const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, amount, publicKey);

    // s'·G == R' + e'·P
    const lhs = G.multiply(s);
    const rhs = Rp.add(P.multiply(ePrime));
    return lhs.equals(rhs);
  } catch {
    // malformed point / invalid encoding → signature is invalid
    return false;
  }
}

// re-export core curve primitives so callers of schnorrBlind don't need a
// separate import of curve.js for the common path
export {
  G,
  n,
  modN,
  scalarToBytes,
  bytesToScalar,
  encodePoint,
  decodePoint,
  randomScalar,
};
