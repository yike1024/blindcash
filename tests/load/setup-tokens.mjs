// tests/load/setup-tokens.mjs — Phase 5: 为 k6 支付压测预生成 valid token
//
// k6 的 JS 运行时不支持 secp256k1 标量乘法，无法在 k6 内完成 4-move 盲签名
// 协议。所以用 Node 脚本（复用项目真实的 crypto/ 模块）批量生成 valid token，
// 写入 tokens.json，k6 脚本读取后压测 /api/payment。
//
// 用法：
//   node tests/load/setup-tokens.mjs <count> <base_url>
//   例：node tests/load/setup-tokens.mjs 200 http://localhost:4100
//
// 流程：对每个用户 register → deposit 1000 → 4-move 取款 50 → 得到 valid token。
// 输出 tests/load/tokens.json：[{ serial, amount, R_prime, s_prime, key_id }]
//
// 注意：此脚本会在服务端留下 <count> 个用户 + 交易记录。压测前建议用干净 DB。

import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// 项目 crypto 模块（backend/src/crypto/*）——纯 JS，Node 可直接 import
import { generateBlinders, computeBlindedCommitment, unblindResponse, modN } from '../../backend/src/crypto/client/blinding.js';
import { hashToScalar } from '../../backend/src/crypto/server/hashToScalar.js';
import { bytesToScalar, scalarToBytes } from '../../backend/src/crypto/server/curve.js';
import { TOKEN_DOMAIN_TAG } from '../../backend/src/crypto/client/protocolConstants.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BASE_URL = process.argv[3] || 'http://localhost:4100';
const COUNT = parseInt(process.argv[2] || '50', 10);
const AMOUNT = 50;

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}
function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
function scalarToHex(s) {
  return bytesToHex(scalarToBytes(s));
}
function hexToScalar(hex) {
  return bytesToScalar(hexToBytes(hex));
}

async function api(path, { method = 'POST', token, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let json;
  try { json = await res.json(); } catch { json = null; }
  return { status: res.status, body: json };
}

function makeUser(i) {
  return {
    username: `k6user_${Date.now()}_${i}`,
    password: `K6pass!${i}_${randomBytes(4).toString('hex')}`,
  };
}

// 完整 4-move 客户端协议（复用 tests/withdrawal.test.js 的 clientBuildCandidates）
function clientBuildCandidates(RHexList, amount, publicKeyHex) {
  const publicKey = hexToBytes(publicKeyHex);
  const candidates = [];
  const blinders = [];
  for (let i = 0; i < RHexList.length; i++) {
    const R = hexToBytes(RHexList[i]);
    const bl = generateBlinders();
    const RPrime = computeBlindedCommitment(R, bl.alpha, bl.beta, publicKey);
    const serial = new Uint8Array(32);
    globalThis.crypto.getRandomValues(serial);
    const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, amount, publicKey);
    const e = modN(ePrime + bl.beta);
    candidates.push({
      e: scalarToHex(e),
      R_prime: bytesToHex(RPrime),
      serial: bytesToHex(serial),
    });
    blinders.push({ alpha: bl.alpha, beta: bl.beta });
  }
  return { candidates, blinders };
}

async function generateOneToken(token) {
  // ① init
  const init = await api('/api/withdraw/init', { token, body: { amount: AMOUNT } });
  if (init.status !== 201) throw new Error(`init failed: ${init.status} ${JSON.stringify(init.body)}`);
  const { session_id, R, N } = init.body;

  // 取公钥
  const pub = await api('/api/bank/pubkey', { method: 'GET' });
  const publicKeyHex = pub.body.public_key;

  // ③ submit — 客户端盲化
  const { candidates, blinders } = clientBuildCandidates(R, AMOUNT, publicKeyHex);
  const submit = await api('/api/withdraw/submit', { token, body: { session_id, candidates } });
  if (submit.status !== 200) throw new Error(`submit failed: ${submit.status} ${JSON.stringify(submit.body)}`);
  const { j } = submit.body;

  // ⑤ reveal — 揭示 i≠j 的 α/β
  const revealed = [];
  for (let i = 0; i < N; i++) {
    if (i === j) continue;
    revealed.push({ i, alpha: scalarToHex(blinders[i].alpha), beta: scalarToHex(blinders[i].beta) });
  }
  const reveal = await api('/api/withdraw/reveal', { token, body: { session_id, revealed } });
  if (reveal.status !== 200) throw new Error(`reveal failed: ${reveal.status} ${JSON.stringify(reveal.body)}`);
  const sJ = hexToScalar(reveal.body.s_j);
  const key_id = reveal.body.key_id;

  // unblind: s' = (s_j + α_j) mod n
  const sPrime = unblindResponse(sJ, blinders[j].alpha);

  return {
    serial: candidates[j].serial,
    amount: AMOUNT,
    R_prime: candidates[j].R_prime,
    s_prime: scalarToHex(sPrime),
    key_id,
  };
}

console.log(`Generating ${COUNT} valid tokens from ${BASE_URL}...`);
const tokens = [];

for (let i = 0; i < COUNT; i++) {
  const u = makeUser(i);
  const reg = await api('/api/auth/register', { body: { ...u, role: 'customer' } });
  if (reg.status !== 201) throw new Error(`register ${i}: ${reg.status}`);
  const token = reg.body.token;

  const dep = await api('/api/bank/deposit', { token, body: { amount: 1000 } });
  if (dep.status !== 200) throw new Error(`deposit ${i}: ${dep.status}`);

  const t = await generateOneToken(token);
  tokens.push(t);

  if ((i + 1) % 10 === 0) console.log(`  ${i + 1}/${COUNT} done`);
}

writeFileSync(join(__dirname, 'tokens.json'), JSON.stringify(tokens, null, 2));
console.log(`Wrote ${tokens.length} tokens to tests/load/tokens.json`);
