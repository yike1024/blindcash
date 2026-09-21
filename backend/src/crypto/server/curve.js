// crypto/server/curve.js — secp256k1 wrapper (server side, Node-only)
//
// v3 §2.1: curve = secp256k1, generator G, order n, 33-byte compressed point
// encoding (0x02/0x03 prefix + 32B x), 32-byte big-endian scalar.
//
// Built on @noble/secp256k1 (same lib as cryptobank/backend/src/crypto/keys.js).
// The library exposes a Point class with .mul / .add / .toRawBytes / .fromHex,
// which is exactly what Schnorr blind signing needs (scalar mult, point add,
// encode/decode). This module wraps those primitives into the names used by
// the v3 outline so the protocol code reads like the spec.
//
// NOTE on "elliptic" in the v3 outline §2.1: the outline text says "复用 elliptic
// 库" but cryptobank actually uses @noble/secp256k1. We follow cryptobank's
// actual choice (noble) for cross-project consistency — same curve, smaller
// footprint, browser-compatible.

import { CURVE, Point, utils as nobleUtils } from '@noble/secp256k1';

// re-export Point so client modules (which import from '../server/curve.js')
// don't need to also import @noble/secp256k1 directly — single source of truth
export { Point };

/**
 * Curve order n (secp256k1).
 * 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 */
export const n = CURVE.n;

/**
 * Generator point G (secp256k1 base point).
 */
export const G = Point.BASE;

/**
 * Point at infinity (identity element of the group).
 */
export const INFINITY = Point.ZERO;

/**
 * Validate that a bigint is a valid scalar: 1 ≤ x < n.
 * (0 is not a valid private key; n and above are out of range.)
 * @param {bigint} s
 * @returns {boolean}
 */
export function isValidScalar(s) {
  return s >= 1n && s < n;
}

/**
 * Reduce a bigint modulo n (handles negative correctly).
 * @param {bigint} s
 * @returns {bigint} s mod n, in [0, n)
 */
export function modN(s) {
  const r = s % n;
  return r < 0n ? r + n : r;
}

/**
 * Convert a 32-byte big-endian Uint8Array to a scalar bigint.
 * Does NOT reduce mod n — caller must call modN if needed.
 * @param {Uint8Array} bytes 32 bytes
 * @returns {bigint}
 */
export function bytesToScalar(bytes) {
  if (bytes.length !== 32) {
    throw new Error(`bytesToScalar: expected 32 bytes, got ${bytes.length}`);
  }
  let s = 0n;
  for (let i = 0; i < 32; i++) s = (s << 8n) | BigInt(bytes[i]);
  return s;
}

/**
 * Convert a scalar bigint to a 32-byte big-endian Uint8Array.
 * @param {bigint} s
 * @returns {Uint8Array}
 */
export function scalarToBytes(s) {
  if (s < 0n) throw new Error('scalarToBytes: negative scalar');
  const out = new Uint8Array(32);
  let v = s;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error('scalarToBytes: scalar >= 2^256');
  return out;
}

/**
 * Encode a Point as 33-byte compressed (0x02/0x03 prefix + 32B x).
 * @param {Point} pt
 * @returns {Uint8Array} 33 bytes
 */
export function encodePoint(pt) {
  return pt.toRawBytes(true); // true = compressed
}

/**
 * Decode a 33-byte compressed point (full on-curve check).
 * Throws on malformed input — callers that want a boolean check should use
 * isOnCurve() instead.
 * @param {Uint8Array|string} bytes 33 bytes (Uint8Array or hex string)
 * @returns {Point}
 */
export function decodePoint(bytes) {
  const buf = typeof bytes === 'string' ? hexToBytesLocal(bytes) : bytes;
  if (buf.length !== 33) {
    throw new Error(`decodePoint: expected 33 bytes, got ${buf.length}`);
  }
  // Point.fromHex throws if the point is not on the curve (it verifies the
  // encoding + reconstructs y + checks y² = x³ + 7).
  return Point.fromHex(bytesToHexLocal(buf));
}

/**
 * Full on-curve check: 33 bytes, prefix 0x02/0x03, AND point decodes.
 * This is the SERVER-side check (full validation). The CLIENT side
 * (crypto/client/pointFormat.js) only checks the format, not full on-curve.
 * @param {Uint8Array|string} bytes
 * @returns {boolean}
 */
export function isOnCurve(bytes) {
  try {
    decodePoint(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * Scalar multiplication: k · P.
 * @param {bigint} k
 * @param {Point} P
 * @returns {Point}
 */
export function scalarMult(k, P) {
  return P.multiply(k);
}

/**
 * Point addition: P + Q (both must be on curve, not infinity-vs-infinity edge).
 * @param {Point} P
 * @param {Point} Q
 * @returns {Point}
 */
export function pointAdd(P, Q) {
  return P.add(Q);
}

/**
 * Generate a random scalar in [1, n-1] using @noble/secp256k1's CSPRNG.
 * (Server-side; uses Node crypto under the hood — the client side uses
 * crypto.getRandomValues via crypto/client/blinding.js.)
 * @returns {bigint}
 */
export function randomScalar() {
  // utils.randomPrivateKey() returns a 32-byte Uint8Array that is a valid
  // private key (< n, ≠ 0). We convert to bigint for arithmetic.
  const bytes = nobleUtils.randomPrivateKey();
  return bytesToScalar(bytes);
}

// ── internal hex helpers (avoid circular import with utils/hex.js) ──
// We inline these to keep crypto/server/curve.js free of cross-module deps;
// utils/hex.js is the public-facing helper, this module has its own private
// copy used only by decodePoint/isOnCurve.
function bytesToHexLocal(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
function hexToBytesLocal(hex) {
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length input: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
