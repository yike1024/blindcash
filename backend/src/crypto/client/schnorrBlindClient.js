// crypto/client/schnorrBlindClient.js — client-side challenge compute + verify
//
// v3 §5 step 6: the client side of the protocol — compute (R', e', e) before
// submit, and verifySig before showing the user "you have a token".
//
// The verifySig here is a PURE CLIENT-SIDE PREVIEW (used by the merchant's
// "local pre-verify" button on the Pay page, M6). The bank ALWAYS does its
// own server-side verifySig (crypto/server/schnorrBlind.js) before deposit —
// a client cannot trust its own verification result without server
// confirmation. But the local preview is a nice UX/teaching touch: it shows
// "anyone can verify" — the public-verifiability property of blind eCash.

import { Point, G, n, modN } from '../server/curve.js';
import { hashToScalar } from '../server/hashToScalar.js';
import { TOKEN_DOMAIN_TAG } from '../../config/bank.js';

/**
 * User-side: compute the blinded challenge triple (R', e', e) from inputs.
 *
 *   R' = R + α·G + β·P                       (computed here or via blinding.js)
 *   e' = H(tag ‖ R' ‖ serial ‖ amount ‖ P) mod n
 *   e  = (e' + β) mod n                       (the BLINDED challenge sent to bank)
 *
 * @param {Uint8Array} R          33-byte compressed bank commitment
 * @param {bigint}     alpha      α (random blinder)
 * @param {bigint}     beta       β (random blinder)
 * @param {Uint8Array} serial     32-byte coin serial
 * @param {number}     amount     positive integer
 * @param {Uint8Array} publicKey  33-byte compressed bank public key P
 * @returns {{ RPrime: Uint8Array, ePrime: bigint, e: bigint }}
 */
export function userComputeChallenge(R, alpha, beta, serial, amount, publicKey) {
  // R' = R + α·G + β·P
  const Rp = Point.fromHex(bytesToHex(R));
  const P = Point.fromHex(bytesToHex(publicKey));
  const alphaG = G.multiply(alpha);
  const betaP = P.multiply(beta);
  const RPrime = Rp.add(alphaG).add(betaP);
  const RPrimeBytes = RPrime.toRawBytes(true);

  // e' = H(tag ‖ R' ‖ serial ‖ amount ‖ P)
  const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrimeBytes, serial, amount, publicKey);

  // e = (e' + β) mod n
  const e = modN(ePrime + beta);

  return { RPrime: RPrimeBytes, ePrime, e };
}

/**
 * Client-side (merchant) signature preview: verify s'·G == R' + e'·P.
 *
 * This is the SAME check the bank server runs, but executed in the browser
 * (the merchant pre-verifies a token before submitting it for deposit).
 * It's a UX/teaching convenience, not a security boundary — the bank's
 * server-side verifySig is the authority.
 *
 * @param {Uint8Array} RPrime     33-byte compressed R'
 * @param {bigint|Uint8Array} sPrime   s' (32-byte BE or bigint)
 * @param {Uint8Array} serial     32-byte coin serial
 * @param {number}     amount     positive integer
 * @param {Uint8Array} publicKey  33-byte compressed bank public key P
 * @returns {boolean}
 */
export function verifySig(RPrime, sPrime, serial, amount, publicKey) {
  try {
    let s;
    if (typeof sPrime === 'bigint') {
      s = sPrime;
    } else if (sPrime instanceof Uint8Array && sPrime.length === 32) {
      s = bytesToScalarLocal(sPrime);
    } else {
      return false;
    }
    if (s < 1n || s >= n) return false;

    const Rp = Point.fromHex(bytesToHex(RPrime));
    const P = Point.fromHex(bytesToHex(publicKey));
    const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, amount, publicKey);

    const lhs = G.multiply(s);
    const rhs = Rp.add(P.multiply(ePrime));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

// internal — bytesToScalar (inlined; mirror of curve.js bytesToScalar but
// kept local so the client bundle doesn't pull extra exports)
function bytesToScalarLocal(bytes) {
  if (bytes.length !== 32) {
    throw new Error(`bytesToScalar: expected 32 bytes, got ${bytes.length}`);
  }
  let s = 0n;
  for (let i = 0; i < 32; i++) s = (s << 8n) | BigInt(bytes[i]);
  return s;
}

// internal — bytesToHex (inlined for bundle minimization)
function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
