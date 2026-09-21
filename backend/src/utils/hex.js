// utils/hex.js — shared byte/hex helpers used across crypto modules
// (copied verbatim from cryptobank/backend/src/utils/hex.js for consistency)
export function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error(`hexToBytes: odd-length input: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}
