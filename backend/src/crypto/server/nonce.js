// crypto/server/nonce.js — per-session nonce derivation (RFC6979-style)
//
// v3 §2.3 + ISOLATION §5: every session generates N fresh k_i in [1, n-1].
// We DO NOT reuse k across sessions (nonce reuse would let an attacker
// solve s₁-s₂ = (e₁-e₂)·x for the private key x — the Schnorr nonce-reuse
// catastrophe).
//
// We bind each k to (session_id, candidate_index) via HMAC-SHA256 with the
// bank's private key x as the HMAC key. This is RFC6979-style deterministic
// derivation: given the same (x, session_id, i), we always get the same k_i,
// which makes the protocol reproducible for tests/audit AND inherently
// non-reused because session_id is unique per withdrawal.
//
// IMPORTANT: this is the BANK-side nonce used to compute R_i = k_i·G at init.
// It is NOT the user's α/β (those are client-side, see crypto/client/blinding.js).
//
// The output k is reduced mod (n-1) then +1 to map to [1, n-1] (avoids k=0).

import { createHmac } from 'node:crypto';
import { n } from './curve.js';
import { bytesToScalar, modN } from './curve.js';

/**
 * Derive k_i deterministically from (x, session_id, i) using HMAC-SHA256.
 *
 * @param {Uint8Array} privateKey  32-byte bank private key x (HMAC key)
 * @param {string}     sessionId   unique per-withdrawal session identifier
 * @param {number}     i           candidate index (0-based or 1-based — caller must be consistent)
 * @returns {bigint} k_i in [1, n-1]
 */
export function deriveNonce(privateKey, sessionId, i) {
  // HMAC-SHA256(key=privateKey, msg=sessionId ‖ i)
  // We use 32-bit BE encoding for i to keep the message unambiguous.
  const iBytes = new Uint8Array(4);
  let v = i >>> 0;
  iBytes[0] = (v >>> 24) & 0xff;
  iBytes[1] = (v >>> 16) & 0xff;
  iBytes[2] = (v >>> 8) & 0xff;
  iBytes[3] = v & 0xff;

  // Node's createHmac accepts ArrayBuffer / Uint8Array as key and message.
  const h = createHmac('sha256', privateKey);
  h.update(sessionId, 'utf8');
  h.update(iBytes);
  const digest = h.digest();          // 32 bytes Buffer

  // map 32 bytes → bigint in [0, n-1] via reduction mod (n-1) then +1 → [1, n-1]
  // mod (n-1) avoids the k=n case; +1 shifts 0 → 1.
  let k = bytesToScalar(new Uint8Array(digest));  // [0, 2^256-1]
  k = k % (n - 1n);                                // [0, n-2]
  k = k + 1n;                                       // [1, n-1]
  return k;
}

/**
 * Derive N fresh nonces for a session.
 *
 * @param {Uint8Array} privateKey  32-byte bank private key
 * @param {string}     sessionId
 * @param {number}     N           candidate count
 * @returns {bigint[]} N scalars, each in [1, n-1]
 */
export function deriveNonces(privateKey, sessionId, N) {
  const out = new Array(N);
  for (let i = 0; i < N; i++) {
    out[i] = deriveNonce(privateKey, sessionId, i);
  }
  return out;
}

// re-export curve helpers for callers
export { n, modN };
