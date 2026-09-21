// utils/pointEncoding.js — 33-byte compressed point helpers (server side)
//
// v3 §4.1: "33-byte 压缩点编解码 + isOnCurve（后端用，与 crypto/server/curve.js 同源）"
//
// This module is a thin re-export of crypto/server/curve.js's point
// encoding/decoding surface, so routes/services that just need to encode or
// validate a public key don't have to import from the crypto/ subtree
// directly. The actual logic lives in crypto/server/curve.js — this is a
// convenience surface, not a parallel implementation.

export {
  encodePoint,
  decodePoint,
  isOnCurve,
  scalarToBytes,
  bytesToScalar,
  modN,
  isValidScalar,
} from '../crypto/server/curve.js';
