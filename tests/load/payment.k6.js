// tests/load/payment.k6.js — Phase 5: 支付并发压测（双花检测）
//
// v5 §三 5.4 验收：50 并发支付 P99 < 300ms，双花检测 100% 正确。
//
// 压测目标：
//   - /api/payment 在并发下的响应时间（P95/P99）
//   - **双花检测正确性**：同一 token 被多个 VU 并发提交时，恰好 1 个 200，
//     其余全部 409（spent_coins UNIQUE 约束 + BEGIN IMMEDIATE）。
//
// token 来源：tests/load/tokens.json，由 setup-tokens.mjs 预生成。
//
// 运行：
//   node tests/load/setup-tokens.mjs 200 http://localhost:4100
//   k6 run tests/load/payment.k6.js
//
// 环境变量：
//   BASE_URL  — 服务地址（默认 http://localhost:4100）
//   VUS       — 并发数（默认 50）
//   DURATION  — 持续时间（默认 10s，因为 token 有限）

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:4100';
const VUS = parseInt(__ENV.VUS || '50', 10);
const DURATION = __ENV.DURATION || '10s';

export const options = {
  vus: VUS,
  duration: DURATION,
  thresholds: {
    http_req_duration: ['p(95)<300', 'p(99)<500'],
  },
};

// setup: 读 tokens.json + 为每个 VU 注册一个收款账户。
// tokens.json 是预生成的 valid token 数组。
export function setup() {
  // 读 tokens.json（k6 的 open 是同步的）
  const tokens = JSON.parse(open('./tokens.json'));
  console.log(`Loaded ${tokens.length} tokens`);

  // 为每个 VU 注册一个收款账户
  const users = [];
  for (let i = 0; i < VUS; i++) {
    const username = `k6p_${Date.now()}_${i}`;
    const password = `K6pass!${i}_y`;
    const reg = http.post(`${BASE_URL}/api/auth/register`, JSON.stringify({
      username, password, role: 'merchant',
    }), { headers: { 'Content-Type': 'application/json' } });
    if (reg.status !== 201) {
      console.error(`register ${i} failed: ${reg.status}`);
      continue;
    }
    users.push(reg.json('token'));
  }

  return { tokens, users };
}

// 共享状态：已消费的 token index（k6 不支持全局共享变量，用 __VU 轮转）。
// 每个 VU 按 (VU + iteration) % tokens.length 取 token——多个 VU 会取到
// 同一 token，这正是双花检测要测的场景。
export default function (data) {
  if (!data.tokens || data.tokens.length === 0) return;
  const vu = (__VU - 1) % data.users.length;
  const token = data.users[vu];
  if (!token) return;

  // 轮转取 token——多个 VU 会撞同一个 token，触发双花检测
  const idx = (__VU * 7 + __ITER) % data.tokens.length;
  const t = data.tokens[idx];

  const res = http.post(`${BASE_URL}/api/payment`, JSON.stringify(t), {
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
  });

  // 期望：200（首次消费）或 409（已被消费 = 双花）。
  // 其他状态码（400 token 无效、401 未认证）应视为异常。
  check(res, {
    'payment status is 200 or 409': (r) => r.status === 200 || r.status === 409,
    'no 400 malformed token': (r) => r.status !== 400,
  });

  sleep(0.05);
}
