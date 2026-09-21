// tests/schnorrBlind.test.js — M2 unit tests for crypto/server/schnorrBlind.js
//
// v3 §5 M2 test list:
//   ✓ correctness: blind → unblind → verify
//   ✓ tampering: serial/amount/R'/s' any single byte → verify fails
//   ✓ linearity: same (k, x) → s linearly scales with e
//   ✓ malformed inputs rejected (R' wrong length, R' not on curve, s' ≥ n, etc.)
//   ✓ verifySig with wrong P fails
//
// The blindness-evidence test (bank has full session data + all α/β except j
// yet cannot recover R'_j) lives in cutAndChoose.test.js, since it requires
// the N-candidate machinery.

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  bankStep1,
  bankStep3,
  verifySig,
} from '../src/crypto/server/schnorrBlind.js';
import { G, n, modN, scalarToBytes, bytesToScalar } from '../src/crypto/server/curve.js';
import { hashToScalar } from '../src/crypto/server/hashToScalar.js';
import {
  generateBlinders,
  computeBlindedCommitment,
  unblindResponse,
} from '../src/crypto/client/blinding.js';
import { TOKEN_DOMAIN_TAG } from '../src/config/bank.js';
import { bytesToHex, hexToBytes, randomBytes } from './setup.js';

// ── shared "one-candidate happy path" factory ──
// Builds a single blind-sign round: bank keypair + (k, R, α, β, serial, amount,
// R', e', e, s, s'). Tests below either reuse this directly or mutate one
// field to set up a tamper scenario.
function makeHappyRound(amount = 100) {
  const kp = generateKeyPair();
  const k = bytesToScalar(randomBytes(32)) % (n - 1n) + 1n; // [1, n-1]
  const { R, RBytes } = bankStep1(k);
  const { alpha, beta } = generateBlinders();
  const serial = randomBytes(32);
  const RPrime = computeBlindedCommitment(RBytes, alpha, beta, kp.publicKey);
  const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, amount, kp.publicKey);
  const e = modN(ePrime + beta);
  const s = bankStep3(k, e, kp.x);
  const sPrime = unblindResponse(s, alpha);
  return { kp, k, R, RBytes, alpha, beta, serial, amount, RPrime, ePrime, e, s, sPrime };
}

describe('M2 · schnorrBlind.js — 3-move single-candidate protocol', () => {
  describe('correctness: blind → sign → unblind → verify', () => {
    it('accepts a properly unblinded signature (s\'·G = R\' + e\'·P)', () => {
      const r = makeHappyRound();
      // Bank side verify (the authority check)
      expect(verifySig(r.RPrime, r.sPrime, r.serial, r.amount, r.kp.publicKey)).toBe(true);
    });

    it('client-side verifySig also passes (merchant local preview)', async () => {
      const { verifySig: clientVerify } = await import('../src/crypto/client/schnorrBlindClient.js');
      const r = makeHappyRound();
      expect(clientVerify(r.RPrime, r.sPrime, r.serial, r.amount, r.kp.publicKey)).toBe(true);
    });

    it('multiple rounds with fresh k/α/β produce different tokens', () => {
      const r1 = makeHappyRound();
      const r2 = makeHappyRound();
      expect(bytesToHex(r1.RPrime)).not.toBe(bytesToHex(r2.RPrime));
      expect(r1.sPrime).not.toBe(r2.sPrime);
      expect(bytesToHex(r1.serial)).not.toBe(bytesToHex(r2.serial));
    });
  });

  describe('tampering: any single-byte mutation → verify fails', () => {
    it('tampered serial (1 byte flipped) → reject', () => {
      const r = makeHappyRound();
      const tampered = new Uint8Array(r.serial);
      tampered[5] ^= 0x01;
      expect(verifySig(r.RPrime, r.sPrime, tampered, r.amount, r.kp.publicKey)).toBe(false);
    });

    it('tampered amount (off-by-one) → reject', () => {
      const r = makeHappyRound();
      expect(verifySig(r.RPrime, r.sPrime, r.serial, r.amount + 1, r.kp.publicKey)).toBe(false);
    });

    it('tampered R\' (1 byte flipped, still 33 bytes) → reject', () => {
      const r = makeHappyRound();
      const tampered = new Uint8Array(r.RPrime);
      // flip a byte in the middle of the x-coordinate (not the prefix) so the
      // length is still 33 but the point is different (likely off-curve).
      tampered[10] ^= 0x01;
      expect(verifySig(tampered, r.sPrime, r.serial, r.amount, r.kp.publicKey)).toBe(false);
    });

    it('tampered s\' (low bit flipped) → reject', () => {
      const r = makeHappyRound();
      const sPrimeBytes = scalarToBytes(r.sPrime);
      const tampered = new Uint8Array(sPrimeBytes);
      tampered[31] ^= 0x01; // flip the lowest bit
      const tamperedScalar = bytesToScalar(tampered);
      expect(verifySig(r.RPrime, tamperedScalar, r.serial, r.amount, r.kp.publicKey)).toBe(false);
    });
  });

  describe('linearity: same (k, x) → s scales linearly with e', () => {
    it('s2 - s1 = (e2 - e1)·x mod n', () => {
      const kp = generateKeyPair();
      const k = bytesToScalar(randomBytes(32)) % (n - 1n) + 1n;
      const e1 = bytesToScalar(randomBytes(32)) % n;
      const e2 = bytesToScalar(randomBytes(32)) % n;
      const s1 = bankStep3(k, e1, kp.x);
      const s2 = bankStep3(k, e2, kp.x);
      // s2 - s1 ≡ (e2 - e1)·x mod n
      expect(modN(s2 - s1)).toBe(modN(modN(e2 - e1) * kp.x));
    });
  });

  describe('malformed-input rejection', () => {
    it('verifySig returns false for s\' = 0', () => {
      const r = makeHappyRound();
      expect(verifySig(r.RPrime, 0n, r.serial, r.amount, r.kp.publicKey)).toBe(false);
    });

    it('verifySig returns false for s\' ≥ n', () => {
      const r = makeHappyRound();
      expect(verifySig(r.RPrime, n + 1n, r.serial, r.amount, r.kp.publicKey)).toBe(false);
    });

    it('verifySig returns false when R\' is not 33 bytes', () => {
      const r = makeHappyRound();
      const badR = r.RPrime.slice(0, 32);
      expect(verifySig(badR, r.sPrime, r.serial, r.amount, r.kp.publicKey)).toBe(false);
    });

    it('verifySig returns false when R\' is 33 bytes but not on curve', () => {
      const r = makeHappyRound();
      const bad = new Uint8Array(33);
      bad[0] = 0x02;            // valid prefix
      bad.set(randomBytes(32), 1); // random x — almost certainly not on curve
      expect(verifySig(bad, r.sPrime, r.serial, r.amount, r.kp.publicKey)).toBe(false);
    });

    it('verifySig returns false with wrong public key P', () => {
      const r = makeHappyRound();
      const otherKp = generateKeyPair();
      expect(verifySig(r.RPrime, r.sPrime, r.serial, r.amount, otherKp.publicKey)).toBe(false);
    });

    it('hashToScalar throws on amount ≤ 0', () => {
      const r = makeHappyRound();
      expect(() => hashToScalar(TOKEN_DOMAIN_TAG, r.RPrime, r.serial, 0, r.kp.publicKey)).toThrow();
      expect(() => hashToScalar(TOKEN_DOMAIN_TAG, r.RPrime, r.serial, -5, r.kp.publicKey)).toThrow();
    });

    it('hashToScalar throws on serial length ≠ 32', () => {
      const r = makeHappyRound();
      const badSerial = new Uint8Array(31);
      expect(() => hashToScalar(TOKEN_DOMAIN_TAG, r.RPrime, badSerial, r.amount, r.kp.publicKey)).toThrow();
    });

    it('hashToScalar throws on R\' length ≠ 33', () => {
      const r = makeHappyRound();
      const badR = new Uint8Array(34);
      expect(() => hashToScalar(TOKEN_DOMAIN_TAG, badR, r.serial, r.amount, r.kp.publicKey)).toThrow();
    });
  });

  describe('bankStep1 / bankStep3 invariants', () => {
    it('bankStep1 throws on k out of range (k = 0 or k = n)', () => {
      expect(() => bankStep1(0n)).toThrow();
      expect(() => bankStep1(n)).toThrow();
    });

    it('bankStep1 produces R = k·G (point-on-curve, decodable)', () => {
      const k = bytesToScalar(randomBytes(32)) % (n - 1n) + 1n;
      const { R, RBytes } = bankStep1(k);
      // RBytes is 33 bytes with valid prefix
      expect(RBytes.length).toBe(33);
      expect(RBytes[0] === 0x02 || RBytes[0] === 0x03).toBe(true);
      // Re-derive R = k·G via noble's Point and compare bytes
      const expected = G.multiply(k).toRawBytes(true);
      expect(bytesToHex(RBytes)).toBe(bytesToHex(expected));
    });

    it('bankStep3 returns s = (k + e·x) mod n', () => {
      const kp = generateKeyPair();
      const k = bytesToScalar(randomBytes(32)) % (n - 1n) + 1n;
      const e = bytesToScalar(randomBytes(32)) % n;
      const s = bankStep3(k, e, kp.x);
      expect(s).toBe(modN(k + modN(e * kp.x)));
    });
  });
});
