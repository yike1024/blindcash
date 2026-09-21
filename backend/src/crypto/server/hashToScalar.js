// crypto/server/hashToScalar.js — domain-separated hash-to-scalar
//
// v3 §2.1: H(tag ‖ data) with domain separation, output reduced mod n.
//
// We hash the concatenation of the protocol domain tag + the canonical byte
// encoding of every signed field (R' ‖ serial ‖ amount ‖ P). The result is a
// 32-byte SHA-256 digest that we then reduce mod n into a valid scalar for
// the Schnorr equation e = (e' + β) mod n.
//
// Why domain separation: without a tag, an attacker could take a valid
// signature from one protocol/context and reuse it as the "challenge" for
// another. The tag binds the hash to this specific blind-cash deployment.
//
// Why canonical encoding: the bank, the user, and the verifier must all
// produce byte-identical inputs to H. We therefore fix the encoding rules
// (33-byte compressed R', 32-byte serial, 8-byte big-endian amount, 33-byte
// compressed P) here and reuse them on both sides via crypto/client/.

import { sha256 } from '@noble/hashes/sha256';
import { n, modN } from './curve.js';
import { bytesToHex } from '../../utils/hex.js';

/**
 * Canonical byte encoding of the signed message.
 *
 * The signed message is (serial, amount, R', P):
 *   serial: 32 bytes (the user-chosen coin identifier)
 *   amount: 8 bytes big-endian (uint64, smallest currency unit)
 *   R':     33 bytes compressed point (blinded commitment)
 *   P:      33 bytes compressed point (bank's public key)
 *
 * All four fields are length-fixed so there is no ambiguity in parsing —
 * a concatenation without length prefixes is unambiguous because every
 * field has a constant length.
 *
 * @param {Uint8Array} RPrime     33-byte compressed R' (blinded commitment)
 * @param {Uint8Array} serial     32-byte coin serial
 * @param {number}     amount     positive integer (≤ 2^53-1, packed as uint64 BE)
 * @param {Uint8Array} publicKey  33-byte compressed bank public key P
 * @returns {Uint8Array} canonical concatenation, ready to hash
 */
export function canonicalChallengeInput(RPrime, serial, amount, publicKey) {
  if (RPrime.length !== 33) throw new Error(`R' must be 33 bytes (got ${RPrime.length})`);
  if (serial.length !== 32) throw new Error(`serial must be 32 bytes (got ${serial.length})`);
  if (publicKey.length !== 33) throw new Error(`P must be 33 bytes (got ${publicKey.length})`);
  if (!Number.isInteger(amount) || amount <= 0 || amount > 0xFFFFFFFFFFFFFFFF) {
    throw new Error(`amount must be positive uint64 (got ${amount})`);
  }

  // 8-byte big-endian amount
  const amountBytes = new Uint8Array(8);
  let v = BigInt(amount);
  for (let i = 7; i >= 0; i--) {
    amountBytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }

  const out = new Uint8Array(33 + 32 + 8 + 33); // 106 bytes
  out.set(RPrime, 0);
  out.set(serial, 33);
  out.set(amountBytes, 65);
  out.set(publicKey, 73);
  return out;
}

/**
 * H(tag ‖ canonical(R', serial, amount, P)) reduced mod n.
 *
 * Domain separation: the tag bytes are prepended so the same (R', serial,
 * amount, P) tuple yields a different scalar under a different tag — this
 * blocks cross-protocol signature reuse.
 *
 * @param {string} tag       domain separation tag (e.g. 'blindcash-v1')
 * @param {Uint8Array} RPrime     33-byte compressed R'
 * @param {Uint8Array} serial     32-byte coin serial
 * @param {number}     amount     positive uint64
 * @param {Uint8Array} publicKey 33-byte compressed bank public key P
 * @returns {bigint} e' in [1, n-1] (zero-extremely-rare collision reduced to 1)
 */
export function hashToScalar(tag, RPrime, serial, amount, publicKey) {
  const tagBytes = new TextEncoder().encode(tag);
  const canon = canonicalChallengeInput(RPrime, serial, amount, publicKey);
  const input = new Uint8Array(tagBytes.length + canon.length);
  input.set(tagBytes, 0);
  input.set(canon, tagBytes.length);

  const digest = sha256(input); // 32 bytes
  let e = bytesToBigInt(digest);
  e = modN(e);
  // SHA-256 mod n collision-floor: e = 0 is statistically impossible
  // (probability ~ 2^-128 under random oracle assumption). We coalesce to 1
  // so the verification equation remains well-defined (s'·G = R' + 0·P = R'
  // would be trivially satisfiable, breaking the signature). This is the
  // standard FDH defense.
  if (e === 0n) e = 1n;
  return e;
}

// internal helper — same as utils/hex bytesToBigInt but inlined to avoid
// a circular dep (utils/hex.js exports bytesToHex/hexToBytes, not bigint).
function bytesToBigInt(bytes) {
  let s = 0n;
  for (let i = 0; i < bytes.length; i++) s = (s << 8n) | BigInt(bytes[i]);
  return s;
}

// re-export n for callers that need both e' and n (e.g. blind = (e' + β) mod n)
export { n, modN };
export { bytesToHex };
