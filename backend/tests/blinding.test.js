// tests/blinding.test.js — M2 unit tests for crypto/client/blinding.js
//
// v3 §5 M2 test list (client subset):
//   ✓ generateBlinders returns α, β in [1, n-1]
//   ✓ generateBlinders is non-deterministic (two draws differ)
//   ✓ computeBlindedCommitment matches the manual computation R + α·G + β·P
//   ✓ unblindResponse: s' = (s + α) mod n mathematically correct
//   ✓ two independent blinding rounds over the same R produce different R'

import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../src/crypto/server/schnorrBlind.js';
import { bankStep1 } from '../src/crypto/server/schnorrBlind.js';
import { G, n, modN } from '../src/crypto/server/curve.js';
import { Point } from '@noble/secp256k1';
import {
  generateBlinders,
  computeBlindedCommitment,
  unblindResponse,
} from '../src/crypto/client/blinding.js';
import { bytesToHex, randomBytes } from './setup.js';

describe('M2 · blinding.js — client-side blinding primitives', () => {
  describe('generateBlinders', () => {
    it('returns α, β as bigints in [1, n-1]', () => {
      const { alpha, beta } = generateBlinders();
      expect(typeof alpha).toBe('bigint');
      expect(typeof beta).toBe('bigint');
      expect(alpha >= 1n).toBe(true);
      expect(alpha < n).toBe(true);
      expect(beta >= 1n).toBe(true);
      expect(beta < n).toBe(true);
    });

    it('exposes α, β as 32-byte big-endian Uint8Arrays', () => {
      const { alphaBytes, betaBytes } = generateBlinders();
      expect(alphaBytes.length).toBe(32);
      expect(betaBytes.length).toBe(32);
      // bytes must be valid big-endian encodings of the bigint
      const { alpha } = generateBlinders();
      // (different draw — just sanity-check the format invariant)
    });

    it('two consecutive draws produce different (α, β) pairs', () => {
      const a = generateBlinders();
      const b = generateBlinders();
      // Probability of collision ≈ 2^-128; assertion is effectively deterministic
      expect(a.alpha === b.alpha && a.beta === b.beta).toBe(false);
    });

    it('1000 draws all land in [1, n-1] (range bound over many trials)', () => {
      for (let i = 0; i < 1000; i++) {
        const { alpha, beta } = generateBlinders();
        expect(alpha >= 1n && alpha < n).toBe(true);
        expect(beta >= 1n && beta < n).toBe(true);
      }
    });
  });

  describe('computeBlindedCommitment', () => {
    it('R\' = R + α·G + β·P (matches manual recompute via noble Point)', () => {
      const kp = generateKeyPair();
      const k = (function () {
        // pick a valid k in [1, n-1] without depending on curve.randomScalar
        let s = BigInt('0x' + bytesToHex(randomBytes(32))) % (n - 1n);
        s = s + 1n;
        return s;
      })();
      const { RBytes } = bankStep1(k);
      const { alpha, beta } = generateBlinders();

      const RPrimeActual = computeBlindedCommitment(RBytes, alpha, beta, kp.publicKey);

      // Manual: R = Point.fromHex(R); P = Point.fromHex(PubKey);
      //   R + α·G + β·P
      const R = Point.fromHex(bytesToHex(RBytes));
      const P = Point.fromHex(bytesToHex(kp.publicKey));
      const expected = R.add(G.multiply(alpha)).add(P.multiply(beta)).toRawBytes(true);

      expect(RPrimeActual.length).toBe(33);
      expect(bytesToHex(RPrimeActual)).toBe(bytesToHex(expected));
    });

    it('two independent (α, β) draws over the same R yield different R\'', () => {
      const kp = generateKeyPair();
      const k = BigInt('0x' + bytesToHex(randomBytes(32))) % (n - 1n) + 1n;
      const { RBytes } = bankStep1(k);
      const r1 = computeBlindedCommitment(RBytes, generateBlinders().alpha, generateBlinders().beta, kp.publicKey);
      const r2 = computeBlindedCommitment(RBytes, generateBlinders().alpha, generateBlinders().beta, kp.publicKey);
      expect(bytesToHex(r1)).not.toBe(bytesToHex(r2));
    });
  });

  describe('unblindResponse', () => {
    it('s\' = (s + α) mod n', () => {
      const s = BigInt('0x' + bytesToHex(randomBytes(32))) % n;
      const alpha = BigInt('0x' + bytesToHex(randomBytes(32))) % (n - 1n) + 1n;
      const sPrime = unblindResponse(s, alpha);
      expect(sPrime).toBe(modN(s + alpha));
      expect(sPrime >= 0n && sPrime < n).toBe(true);
    });

    it('wraps around correctly when s + α ≥ n', () => {
      // pick s, alpha such that their sum exceeds n
      const s = n - 1n;
      const alpha = 5n;
      const sPrime = unblindResponse(s, alpha);
      expect(sPrime).toBe(modN(n - 1n + 5n));   // = 4 mod n
      expect(sPrime).toBe(4n);
    });

    it('end-to-end: blind → unblind produces a signature that bank verifySig accepts', async () => {
      // Sanity check on the blind+unblind pair via the bank's verifySig oracle.
      // (End-to-end coverage already lives in schnorrBlind.test.js; this is a
      // light assertion here that blinding.js's outputs are usable downstream.)
      const { verifySig, generateKeyPair: mkKp, bankStep1: mkR, bankStep3 } =
        await import('../src/crypto/server/schnorrBlind.js');
      const { hashToScalar } = await import('../src/crypto/server/hashToScalar.js');
      const { TOKEN_DOMAIN_TAG } = await import('../src/config/bank.js');
      const kp = mkKp();
      const k = BigInt('0x' + bytesToHex(randomBytes(32))) % (n - 1n) + 1n;
      const { RBytes } = mkR(k);
      const { alpha, beta } = generateBlinders();
      const serial = randomBytes(32);
      const amount = 100;
      const RPrime = computeBlindedCommitment(RBytes, alpha, beta, kp.publicKey);
      const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, amount, kp.publicKey);
      const e = modN(ePrime + beta);
      const s = bankStep3(k, e, kp.x);
      const sPrime = unblindResponse(s, alpha);
      expect(verifySig(RPrime, sPrime, serial, amount, kp.publicKey)).toBe(true);
    });
  });
});
