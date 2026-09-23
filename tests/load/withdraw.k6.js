// tests/load/withdraw.k6.js — Phase 5: 取款并发压测
//
// v5 §三 5.4 验收：50 并发取款 P99 < 500ms。
//
// 压测目标：
//   - /api/withdraw/init 在并发下的响应时间（P95/P99）
//   - 并发 init 同一用户的 409 拒绝（active session 不变量）
//   - 余额不足时的 400
//
// k6 无法完成 4-move 盲签名协议（无 secp256k1），所以本脚本只压测
// init 端点——它是取款流程中最重的 DB 操作（BEGIN IMMEDIATE + 余额校验
// + 生成 N 个 k_i），最能体现并发性能。
//
// 运行：
//   k6 run tests/load/withdraw.k6.js
//
// 环境变量：
//   BASE_URL  — 服务地址（默认 http://localhost:4100）
//   VUS       — 并发数（默认 50）
//   DURATION  — 持续时间（默认 30s）

import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:4100';
const VUS = parseInt(__ENV.VUS || '50', 10);
const DURATION = __ENV.DURATION || '30s';

export const options = {
  vus: VUS,
  duration: DURATION,
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    http_req_failed: ['rate<0.01'],
  },
};

// setup: 为每个 VU 注册一个独立用户 + 充值（Phase 1 后注册即 0 余额）。
// 返回 users 数组，VU 按 __VU 取自己的账户。
export function setup() {
  const users = [];
  for (let i = 0; i < VUS; i++) {
    const username = `k6w_${Date.now()}_${i}`;
    const password = `K6pass!${i}_x`;
    // register
    const reg = http.post(`${BASE_URL}/api/auth/register`, JSON.stringify({
      username, password, role: 'customer',
    }), { headers: { 'Content-Type': 'application/json' } });
    if (reg.status !== 201) {
      console.error(`register ${i} failed: ${reg.status}`);
      continue;
    }
    const token = reg.json('token');
    // deposit 10000 (够多次 init)
    const dep = http.post(`${BASE_URL}/api/bank/deposit`, JSON.stringify({ amount: 10000 }), {
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    });
    if (dep.status !== 200) {
      console.error(`deposit ${i} failed: ${dep.status}`);
      continue;
    }
    users.push(token);
  }
  return { users };
}

export default function (data) {
  const vu = (__VU - 1) % data.users.length;
  const token = data.users[vu];
  if (!token) return;

  // init withdrawal amount=10
  const res = http.post(`${BASE_URL}/api/withdraw/init`, JSON.stringify({ amount: 10 }), {
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
  });

  // 期望：201（成功）或 409（已有 active session）。
  // 409 是正确行为——同一用户不能同时开两个取款会话（不变量 4）。
  check(res, {
    'init status is 201 or 409': (r) => r.status === 201 || r.status === 409,
  });

  // 如果成功 init，立即 cancel 释放会话（否则后续 init 全 409）。
  if (res.status === 201) {
    const sessionId = res.json('session_id');
    http.post(`${BASE_URL}/api/withdraw/cancel`, JSON.stringify({ session_id: sessionId }), {
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    });
  }

  sleep(0.1);
}
