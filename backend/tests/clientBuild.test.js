// tests/clientBuild.test.js — M2 v3 client-subset bundle-ability + browser-env tests
//
// v3 §5 M2 step 8 + §6 verification matrix M2 row:
//   ✓ crypto/client/* can be bundled by `vite build` (no Node-only syntax)
//   ✓ crypto/client/* functions run in a browser-like environment that
//     only exposes Web Crypto (crypto.getRandomValues), not Node's crypto
//
// Strategy:
//   (a) spawn `npx vite build` in the frontend directory and assert exit 0 +
//       no errors in stderr. The frontend's vite.config.js wires
//       vite-plugin-node-polyfills (M1) so Buffer/process/etc. shims exist;
//       if crypto/client/* has any remaining Node-only API the build will fail
//       with a clear error from esbuild/rollup.
//   (b) switch the vitest environment to happy-dom (a lightweight browser
//       emulation that does NOT expose Node's `crypto` module — only the
//       Web Crypto API via globalThis.crypto). Run generateBlinders +
//       userComputeChallenge + verifySig end-to-end under that env to prove
//       the client subset is genuinely browser-runnable.

// @vitest-environment happy-dom

import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FRONTEND_DIR = join(__dirname, '..', '..', 'frontend');

// Helper: spawn `npx vite build` in the frontend dir, capture stdout/stderr,
// resolve to { code, stderr }. Used to assert the bundle succeeds.
async function runViteBuild () {
  return new Promise((resolve) => {
    // Use npx so we don't depend on a specific vite binary path; on Windows
    // npx lives at node_modules/.bin/npx.cmd, which spawn finds via PATH.
    //
    // NOTE (教授 M6.md 风险 #5 / M7 评估): Node 24 emits a DeprecationWarning
    // "Passing args to a child process with shell option true can lead to
    // security vulnerabilities" when `shell: true` is used with args. We
    // INTENTIONALLY keep `shell: true` here because:
    //   (a) On Windows, `npx` is a `.cmd` shim and Node's spawn() cannot exec
    //       .cmd files directly without a shell — `shell: false` throws
    //       EINVAL (we verified this the hard way in M7).
    //   (b) The args array here is hardcoded (no untrusted user input), so
    //       the shell-injection vector the warning worries about doesn't apply.
    //   (c) The warning is non-blocking and goes to stderr; it doesn't fail
    //       the test. CI noise only.
    // Switching to `execFile` + explicit `cmd.exe /c` would silence the
    // warning but is the same shell exec under a different name — not a
    // meaningful security improvement. Accept the warning as-is.
    const child = spawn('npx', ['vite', 'build'], {
      cwd: FRONTEND_DIR,
      shell: true,             // required on Windows to find .cmd shims
      env: { ...process.env, CI: '1' },  // CI=1 → vite uses non-interactive mode
    });
    let stderr = '';
    let stdout = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.on('error', (err) => resolve({ code: -1, stdout: '', stderr: String(err) }));
  });
}

describe('M2 · clientBuild — vite bundle-ability of crypto/client/*', () => {
  // Build can take ~10s on a cold run; let the test breathe.
  it('`npx vite build` in frontend/ exits 0 (no Node-only syntax in client subset)', async () => {
    const { code, stdout, stderr } = await runViteBuild();
    if (code !== 0) {
      // surface the build output for triage
      console.error('--- vite build stdout ---\n' + stdout);
      console.error('--- vite build stderr ---\n' + stderr);
    }
    expect(code).toBe(0);
    // Vite emits a "built in" line on success; we assert at least one of the
    // known success markers appears (defensive — vite 8 wording may change).
    const successMarker = /built in|✓?\s*\d+(\.\d+)?\s*s/i.test(stdout) || stdout.includes('dist');
    expect(successMarker).toBe(true);
  }, 90000);
});

describe('M2 · clientBuild — crypto/client/* runs under happy-dom (browser env)', async () => {
  // The // @vitest-environment happy-dom docblock above switches this whole
  // file into a browser-like env. happy-dom exposes globalThis.crypto (Web
  // Crypto API) but does NOT expose Node's `crypto` module or `node:crypto`.
  // If any crypto/client/* module pulled in `node:crypto` directly, the
  // import below would fail.

  it('generateBlinders runs and returns α/β in [1, n-1]', async () => {
    const { generateBlinders } = await import('../src/crypto/client/blinding.js');
    const { alpha, beta } = generateBlinders();
    const { n } = await import('../src/crypto/server/curve.js');
    expect(typeof alpha).toBe('bigint');
    expect(typeof beta).toBe('bigint');
    expect(alpha >= 1n && alpha < n).toBe(true);
    expect(beta >= 1n && beta < n).toBe(true);
  });

  it('pointFormat.isValidCompressedFormat accepts 33B 0x02/0x03-prefixed', async () => {
    const { isValidCompressedFormat } = await import('../src/crypto/client/pointFormat.js');
    // a known-valid secp256k1 compressed point: the generator G
    const GHex = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    expect(isValidCompressedFormat(GHex)).toBe(true);
    // 32-byte (one short) → reject
    expect(isValidCompressedFormat(GHex.slice(0, 64))).toBe(false);
    // wrong prefix (0x04 = uncompressed) → reject
    expect(isValidCompressedFormat('04' + GHex.slice(2))).toBe(false);
  });

  it('userComputeChallenge + verifySig end-to-end under happy-dom', async () => {
    const { generateKeyPair, bankStep1, bankStep3, verifySig } =
      await import('../src/crypto/server/schnorrBlind.js');
    const { generateBlinders, computeBlindedCommitment, unblindResponse } =
      await import('../src/crypto/client/blinding.js');
    const { userComputeChallenge } = await import('../src/crypto/client/schnorrBlindClient.js');
    const { n } = await import('../src/crypto/server/curve.js');
    const { randomBytes } = await import('./setup.js');

    const kp = generateKeyPair();
    const k = BigInt('0x' + await bytesToHexLocal(randomBytes(32))) % (n - 1n) + 1n;
    const { RBytes } = bankStep1(k);
    const serial = randomBytes(32);
    const amount = 100;

    // Client-side path: user computes (R', e', e) locally
    const { alpha, beta } = generateBlinders();
    const { RPrime, ePrime, e } = userComputeChallenge(RBytes, alpha, beta, serial, amount, kp.publicKey);
    expect(RPrime.length).toBe(33);

    // Bank signs with e (the blinded challenge)
    const s = bankStep3(k, e, kp.x);

    // Client unblinds
    const sPrime = unblindResponse(s, alpha);

    // Bank-side verifySig (server) accepts
    expect(verifySig(RPrime, sPrime, serial, amount, kp.publicKey)).toBe(true);

    // Client-side verifySig (merchant local preview) also accepts
    const { verifySig: clientVerify } = await import('../src/crypto/client/schnorrBlindClient.js');
    expect(clientVerify(RPrime, sPrime, serial, amount, kp.publicKey)).toBe(true);
  });
});

// ── internal: bytesToHex (avoid pulling setup.js's bytesToHex which would
//    need a separate import; we inline for the test's local k derivation)
async function bytesToHexLocal (bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
