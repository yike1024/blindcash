# BlindCash 性能基准测试（Phase 5）

## 环境

- 后端：Node 24 + Express 4 + better-sqlite3（WAL 模式）
- 前端：Vite build + express.static 托管
- 压测工具：[k6](https://k6.io/)

## 前置准备

```bash
# 1. 启动服务（Docker 或本地）
docker compose up -d
# 或
cd backend && npm start

# 2. 生成支付压测用的 valid token
node tests/load/setup-tokens.mjs 200 http://localhost:4100
```

## 取款压测

```bash
k6 run tests/load/withdraw.k6.js
```

**指标**：
- P95 < 500ms
- P99 < 1000ms
- 失败率 < 1%

**说明**：只压测 `/api/withdraw/init`（4-move 协议最重的 DB 操作）。
init 成功后立即 cancel 释放会话，避免后续全 409。

## 支付压测（双花检测）

```bash
k6 run tests/load/payment.k6.js
```

**指标**：
- P95 < 300ms
- P99 < 500ms
- 双花检测 100% 正确：同一 token 并发提交，恰好 1 个 200，其余 409

**说明**：多个 VU 轮转取同一 token，主动制造双花场景。
`spent_coins.serial` UNIQUE 约束 + `BEGIN IMMEDIATE` 保证原子性。

## 基准结果

| 场景 | VUs | P95 | P99 | 双花正确率 | 备注 |
|------|-----|-----|-----|-----------|------|
| 取款 init | 50 | _待填_ | _待填_ | N/A | amount=10, init+cancel 循环 |
| 支付 | 50 | _待填_ | _待填_ | _待填_% | 200 tokens, 轮转制造双花 |

> 运行压测后填入实际数据。压测前用干净 DB（`docker compose down -v && docker compose up -d`）。

## 性能瓶颈分析

better-sqlite3 的写入并发由 `BEGIN IMMEDIATE` 串行化——同一时刻只有
一个写事务。取款 init 和支付都是写事务，高并发下 P99 主要受排队影响。

优化方向（Phase 6 可选）：
- WAL 模式已启用，读不阻塞写
- 如需更高写并发，可考虑将 spent_coins 检查与 INSERT 合并为单条 SQL
  （INSERT ... ON CONFLICT DO NOTHING + 检查 changes），减少往返
- 更激进的优化：分库分表或换 PostgreSQL（超出教学项目范围）

## 文献参考

- [1] k6 文档 — https://k6.io/docs/
- [2] SQLite WAL 模式 — https://www.sqlite.org/wal.html
- [3] OWASP ASVS L1 v4.0.31 §11.1.1 — 速率限制与并发控制
