// crypto/client/pointFormat.js — light client-side point-format check
//
// v3 §2.6 (risk assessment §二-6): the front-end ONLY checks the FORMAT of
// a 33-byte compressed secp256k1 public key:
//   - length === 33
//   - prefix ∈ { 0x02, 0x03 }    (compressed point encoding)
// The full on-curve check (decode the point + verify y² = x³ + 7 mod p)
// is SERVER-side only (crypto/server/curve.js#isOnCurve), because that check
// is computationally heavy and requires the curve lib — we don't want the
// front-end to ship that surface for every UI interaction.
//
// This split mirrors the v3 outline risk decision: front-end gets a fast
// sanity check to fail early on malformed user input (e.g. a serial pasted
// where a pubkey was expected); the BANK's verifySig does the full check.

/**
 * Check whether a byte array / hex string LOOKS LIKE a 33-byte compressed
 * secp256k1 point. Does NOT verify the point is on the curve.
 *
 * @param {Uint8Array|string} input
 * @returns {boolean}
 */
export function isValidCompressedFormat(input) {
  let bytes;
  if (typeof input === 'string') {
    // accept hex strings (66 chars, no 0x prefix)
    if (input.length !== 66) return false;
    if (!/^[0-9a-fA-F]{66}$/.test(input)) return false;
    bytes = hexToBytesLocal(input);
  } else if (input instanceof Uint8Array) {
    bytes = input;
  } else {
    return false;
  }
  if (bytes.length !== 33) return false;
  const prefix = bytes[0];
  return prefix === 0x02 || prefix === 0x03;
}

// ── internal: hex → bytes (light inline; avoids cross-module deps)
function hexToBytesLocal(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
