// routes/bank.js — M3: bank public endpoints
//
// v3 §5 M3 step 5 + §四-5 (风险评估):
//   GET /api/bank/pubkey → no auth, returns { public_key: hex }
//
// Why no auth: the bank's public key P is public knowledge — anyone (merchant,
// customer, observer) needs it to verify token signatures locally. Keeping it
// behind auth would defeat the "anyone can verify" property of blind sigs.
//
// CRITICAL: this route MUST NEVER expose private_key. Only public_key leaves
// the server. The defensive-test in tests/bankKeyService.test.js checks the
// response body for absence of any "private"-ish field.

import { Router } from 'express';
import { getPublicKey } from '../services/bankKeyService.js';
import { bytesToHex } from '../utils/hex.js';

const router = Router();

// GET /api/bank/pubkey
// Returns the bank's 33-byte compressed public key P = x·G as a 66-char hex
// string. No authentication required — P is public.
router.get('/pubkey', (_req, res) => {
  const publicKey = getPublicKey();
  res.json({
    public_key: bytesToHex(publicKey),
    // encoding hint for clients: 33-byte secp256k1 compressed point
    encoding: 'secp256k1-compressed',
    byte_length: 33,
  });
});

export default router;
