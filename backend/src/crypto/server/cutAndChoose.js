// crypto/server/cutAndChoose.js — cut-and-choose verification (bank side)
//
// v3 §2.3: in the 4-move protocol, after the bank picks j, the user reveals
// α_i, β_i for every i ≠ j. The bank verifies each revealed candidate:
//
//   R'_i ?= R_i + α_i·G + β_i·P            (commitment is well-formed)
//   e_i  ?= H(tag ‖ R'_i ‖ serial_i ‖ amount ‖ P) + β_i mod n
//
// If every i ≠ j verifies, the bank signs candidate j (s_j = k_j + e_j·x).
// If ANY candidate fails, the bank aborts (status='aborted') and refunds.
//
// Cheat probability: to forge amount, the user must guess j in advance and
// only fake candidate j. P(j = guessed) = 1/N → 1% at N=100, 10% at N=10.
//
// IMPORTANT (ISOLATION §3.3): this function NEVER receives α_j or β_j.
// The bank must NOT pass them in. The route layer rejects any payload that
// contains α/β for index j (400 error) — that defense is the test surface
// of "blindness invariant 3".

import { Point } from '@noble/secp256k1';
import { G, modN } from './curve.js';
import { hashToScalar } from './hashToScalar.js';
import { TOKEN_DOMAIN_TAG } from '../../config/bank.js';

/**
 * Verify a single revealed candidate (i ≠ j).
 *
 * @param {object}  args
 * @param {Uint8Array} args.R           33-byte compressed R_i (bank's commitment)
 * @param {Uint8Array} args.RPrime      33-byte compressed R'_i (user's blinded commitment)
 * @param {Uint8Array} args.serial      32-byte coin serial for this candidate
 * @param {number}      args.amount     the claimed amount (must be same as init)
 * @param {Uint8Array} args.publicKey   33-byte compressed bank public key P
 * @param {bigint}     args.alpha       α_i — revealed by user
 * @param {bigint}     args.beta        β_i — revealed by user
 * @param {bigint}     args.e           e_i (the blinded challenge user submitted at submit)
 * @returns {boolean}
 */
export function verifyRevealed({ R, RPrime, serial, amount, publicKey, alpha, beta, e }) {
  try {
    const Rp = Point.fromHex(bytesToHex(R));
    const P = Point.fromHex(bytesToHex(publicKey));
    const alphaG = G.multiply(alpha);   // α·G
    const betaP = P.multiply(beta);     // β·P
    const expectedRPrime = Rp.add(alphaG).add(betaP);
    const actualRPrime = Point.fromHex(bytesToHex(RPrime));
    if (!expectedRPrime.equals(actualRPrime)) return false;

    const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, amount, publicKey);
    const expectedE = modN(ePrime + beta);
    if (expectedE !== e) return false;

    return true;
  } catch {
    return false;
  }
}

/**
 * Run verifyRevealed across all revealed candidates; return the index of the
 * first failure (or -1 if all pass).
 *
 * @param {Array} revealed  array of {i, alpha, beta, R, RPrime, serial, e}
 *                          (one per i ≠ j)
 * @param {number} amount  the session's claimed amount (same for all candidates)
 * @param {Uint8Array} publicKey  bank public key
 * @returns {number} -1 if all pass, else the index in `revealed` of first failure
 */
export function verifyAllRevealed(revealed, amount, publicKey) {
  for (let idx = 0; idx < revealed.length; idx++) {
    const r = revealed[idx];
    const ok = verifyRevealed({
      R: r.R,
      RPrime: r.RPrime,
      serial: r.serial,
      amount,
      publicKey,
      alpha: r.alpha,
      beta: r.beta,
      e: r.e,
    });
    if (!ok) return idx;
  }
  return -1;
}

/**
 * Pick a random j ∈ [0, N-1] using rejection sampling (no modular bias).
 *
 * @param {number} N
 * @returns {number}
 */
export function pickRandomJ(N) {
  if (!Number.isInteger(N) || N < 1) throw new Error(`pickRandomJ: N must be ≥ 1 (got ${N})`);
  const mask = 0x7fffffff; // 31-bit mask, fine for N ≤ 2^31
  // Limit on attempts so the function is guaranteed to terminate. The
  // probability of needing more than 64 attempts is below 2^-128 for any
  // reasonable N — well below our 1/N cheat bound.
  for (let attempt = 0; attempt < 64; attempt++) {
    const buf = new Uint8Array(4);
    globalThis.crypto.getRandomValues(buf);
    let v = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) & mask;
    // rejection: only accept if v is in the largest multiple-of-N range
    // below 2^31; otherwise redraw to avoid modular bias.
    const limit = N * Math.floor(0x80000000 / N);
    if (v < limit) return v % N;
  }
  // Fallback: extremely unlikely (prob < 2^-128). Use biased reduction —
  // for any N ≤ 1000 the bias is < 2^-21 which is well below the 1/N cheat
  // bound anyway.
  const buf = new Uint8Array(4);
  globalThis.crypto.getRandomValues(buf);
  const v = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) & mask;
  return v % N;
}

// ── internal: bytes → hex (Point.fromHex accepts hex; this is the canonical
//    encoding path; we inline it to keep this module free of cross-calls to
//    utils/hex.js which would import cycle through curve.js)
function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
