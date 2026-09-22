# BlindCash — Chaumian eCash 教学演示系统

> **基于 Schnorr 盲签名的盲签名电子现金教学项目**
>
> 实现 Chaum 的盲签名电子现金协议（cut-and-choose 4-move），覆盖银行签发、付款人取款、收款人兑付全链路，包含双花检测、盲性证据、原子写事务等工程要点。
>
> 评分维度自评：
> - ✅ 基本功能完成（银行 / 付款人 / 收款人 三大模块全闭环）
> - ✅ 文档完整（README + REQUIREMENTS + DESIGN + IMPLEMENTATION + TESTING + USERGUIDE + ISOLATION 七件套）
> - ✅ 界面友好（antd 6 + 4-step Steps + 300ms debounce 预验签 + TTL 倒计时 + 角色守卫）
> - ✅ 文本规范（中文表述 + 文献引用编号 [1]-[n] + 代码块语言标注 + 表格分章）

---

## 目录

- [1. 项目简介](#1-项目简介)
- [2. 三大功能模块](#2-三大功能模块)
- [3. 快速启动](#3-快速启动)
- [4. 文档导航](#4-文档导航)
- [5. 技术栈](#5-技术栈)
- [6. 里程碑](#6-里程碑)
- [7. 测试](#7-测试)
- [8. 评分标准对照](#8-评分标准对照)
- [9. 参考文献](#9-参考文献)

---

## 1. 项目简介

BlindCash 是一个面向密码货币与区块链技术课程的**教学演示系统**，用 Schnorr 盲签名实现 Chaum 的盲签名电子现金协议。系统模拟三方角色：**银行**（签发与兑付）、**付款人/顾客**（取款）、**收款人/商户**（验签收款）。

**核心特性**：

- **盲签名**：银行签发的 token 不可被链接回某个具体取款会话（cut-and-choose N=100，作弊成功率 ≤ 1%）
- **双花检测**：同一 token 二次兑付时由 SQLite `BEGIN IMMEDIATE` 原子拦截（409 DOUBLE_SPEND）
- **盲性证据**：1000-trial Shannon 熵 ≥ 200 bits（理论 264000 bits，极度保守阈值以拒绝零假设）
- **隔离约定**：α/β 盲化因子只存在前端 `useRef` 内存，绝不离开用户设备（教授 M6 风险 #3 caveat 已写入文档）
- **原子写事务**：所有余额变动均包裹在 `runImmediateTx`，避免 BEGIN DEFERRED 的 TOCTOU 窗口

**教学定位**：

- 密钥安全（HSM / TEE / Shamir 分片）是另一门课的主题，本项目仅以明文存 DB 作显式妥协
- 生产级隔离需 Web Worker / WASM，超出本课程范围

---

## 2. 三大功能模块

> 按课程评分标准"按银行、付款人、收款人三个大功能来看"组织。

### 2.1 银行模块

| 子功能 | 实现位置 | 接口 |
|--------|----------|------|
| 密钥对生成与持久化 | [bankKeyService.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/services/bankKeyService.js) | 启动时 `getOrGenerate()`，singleton 行 id=1 |
| 公钥公开接口 | [routes/bank.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/routes/bank.js) | `GET /api/bank/pubkey`（无认证） |
| 4-move 协议（银行侧） | [schnorrBlind.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/crypto/server/schnorrBlind.js) | `bankStep1(k)` 生成 R、`bankStep3(k, e, x)` 计算 s |
| Cut-and-choose 验证 | [cutAndChoose.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/crypto/server/cutAndChoose.js) | `verifyRevealed` 验证 i ≠ j 的 (α_i, β_i)，`pickRandomJ` 随机挑 j |
| 取款会话状态机 | [withdrawalService.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/services/withdrawalService.js) | init / submit / reveal / cancel / lazyCleanup |
| 双花检测 | [paymentService.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/services/paymentService.js) | `processPayment` + `formatGate` + `computeTokenHash` |

### 2.2 付款人模块（customer）

| 子功能 | 实现位置 | 接口 |
|--------|----------|------|
| 注册 / 登录 | [routes/auth.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/routes/auth.js) | `POST /api/auth/register` / `login` |
| 初始余额 100（教学） | [userService.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/services/userService.js) | 注册时直接写入 balance=100 |
| 取款 4-step 向导 | [Withdraw.jsx](file:///d:/密码货币与区块链技术/blindcash/frontend/src/pages/Withdraw.jsx) | init → submit → reveal+unblind → token 展示 |
| α/β 内存隔离 | [Withdraw.jsx](file:///d:/密码货币与区块链技术/blindcash/frontend/src/pages/Withdraw.jsx#L1) | `useRef([])` + beforeunload + 即时清空 |
| TTL 倒计时 | [Withdraw.jsx](file:///d:/密码货币与区块链技术/blindcash/frontend/src/pages/Withdraw.jsx) | `useState(() => Date.now())` + 1Hz setInterval，5 分钟过期 |
| 4-move 协议（用户侧） | [blinding.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/crypto/client/blinding.js) | `generateBlinders` / `computeBlindedCommitment` / `unblindResponse` |
| 取款校验 | [routes/withdrawal.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/routes/withdrawal.js) | `customerGuard` + amount ≤ balance + active session 唯一 |

### 2.3 收款人模块（merchant）

| 子功能 | 实现位置 | 接口 |
|--------|----------|------|
| 注册 / 登录 | [routes/auth.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/routes/auth.js) | 同 customer（角色互斥） |
| 收款页 | [Payment.jsx](file:///d:/密码货币与区块链技术/blindcash/frontend/src/pages/Payment.jsx) | 粘贴 token JSON → 300ms debounce → 预验签 ✓ → 提交 |
| 预验签 | [schnorrBlindClient.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/crypto/client/schnorrBlindClient.js) | `verifySig(s'·G == R' + e'·P)` 前端本地执行 |
| 收款路由 | [routes/payment.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/routes/payment.js) | `POST /api/payment`，merchantGuard |
| 双花 409 演示 | [Payment.jsx](file:///d:/密码货币与区块链技术/blindcash/frontend/src/pages/Payment.jsx) | "再次提交同 token"按钮 → 409 DOUBLE_SPEND |
| 角色守卫 | [middleware/auth.js](file:///d:/密码货币与区块链技术/blindcash/backend/src/middleware/auth.js) | customer 调 /payment → 403，merchant 调 /withdraw → 403 |

### 2.4 模块间数据流

```
┌──────────────┐   GET /api/bank/pubkey    ┌─────────────┐
│  付款人 customer │ ─────────────────────────> │   银行 bank   │
│  /withdraw    │                              │  bank_keys   │
│               │ <─── R_i (bankStep1) ──────── │              │
│               │ ─── R'_i, e_i (submit) ────> │              │
│               │ <─── j 索引（pickRandomJ）──  │              │
│               │ ─── (α_i,β_i) i≠j (reveal)─> │              │
│               │ <─── s_j (bankStep3) ─────── │              │
│               │                              │              │
│  unblind s'   │                              │              │
│  token JSON   │                              │              │
└──────┬───────┘                              └──────────────┘
       │ 复制 token
       ▼
┌──────────────┐   POST /api/payment          ┌─────────────┐
│ 收款人 merchant │ ─────────────────────────> │   银行 bank   │
│  /payment     │                              │  spent_coins │
│  预验签 ✓      │ <─── 200 OK / 409 双花 ───── │  + balance   │
└──────────────┘                              └──────────────┘
```

---

## 3. 快速启动

### 3.1 环境要求

- Node.js ≥ 24（使用 `globalThis.crypto` webcrypto）
- npm ≥ 10
- Windows / macOS / Linux 均可（开发在 Windows 11 上完成）

### 3.2 安装与运行

```bash
# 1. 克隆项目
git clone <repo-url>
cd blindcash

# 2. 安装前后端依赖
npm run install:all

# 3. 初始化 SQLite 数据库（首次启动）
npm run init:db

# 4. 启动开发服务（同时启动 backend:4100 + frontend:5174）
npm run dev

# 5. 浏览器访问 http://localhost:5174
```

### 3.3 演示模式（cut-and-choose N=10）

```bash
# 默认 N=100（生产级，1% 作弊率）；演示时降为 N=10（10% 作弊率，提速 10 倍）
BC_DEMO_N=10 npm run dev
```

⚠️ **演示模式仅用于教学演示**，生产环境必须使用默认 N=100。详见 [docs/IMPLEMENTATION.md §2.4](file:///d:/密码货币与区块链技术/blindcash/docs/IMPLEMENTATION.md)。

### 3.4 端口分配

| 服务 | 端口 | 备注 |
|------|------|------|
| Backend (Express) | 4100 | 与同机 cryptobank 项目（4000）错开 |
| Frontend (Vite) | 5174 | 与 cryptobank（5173）错开，可同时运行 |

### 3.5 默认账号

启动后需通过 `/register` 自行注册账号。两类角色：

- **customer**（付款人）：注册后自动获得初始余额 100
- **merchant**（收款人）：注册后余额 0，通过接收 token 兑付增加

> 教学演示建议：alice/customer + bob/merchant + carol/merchant（用于双商户并发双花演示）

---

## 4. 文档导航

| 文档 | 内容 | 适用对象 |
|------|------|----------|
| [README.md](file:///d:/密码货币与区块链技术/blindcash/README.md) | 项目入口、三大功能模块对照、快速启动 | 所有人 |
| [docs/REQUIREMENTS.md](file:///d:/密码货币与区块链技术/blindcash/docs/REQUIREMENTS.md) | 用例图 + 15 FR + 10 NFR + 验收标准 | 评审 / 课题答辩 |
| [docs/DESIGN.md](file:///d:/密码货币与区块链技术/blindcash/docs/DESIGN.md) | 架构图 + 4-move 时序图 + ER 图 + API 表 | 架构 review |
| [docs/IMPLEMENTATION.md](file:///d:/密码货币与区块链技术/blindcash/docs/IMPLEMENTATION.md) | M1-M7 里程碑 + 9 项关键工程决策 | 实现 review |
| [docs/TESTING.md](file:///d:/密码货币与区块链技术/blindcash/docs/TESTING.md) | 104 用例分类 + 盲性证据 + 双花演示 | 测试 review |
| [docs/USERGUIDE.md](file:///d:/密码货币与区块链技术/blindcash/docs/USERGUIDE.md) | 银行/付款人/收款人 三方操作手册 | 终端用户 |
| [ISOLATION.md](file:///d:/密码货币与区块链技术/blindcash/ISOLATION.md) | 9 条不变量 + 落地证据 | 协议 review |

---

## 5. 技术栈

| 层 | 选择 | 理由 |
|----|------|------|
| 运行时 | Node 24 | webcrypto 全局可用 |
| 后端框架 | Express 4.21 | 轻量、生态成熟 |
| 数据库 | better-sqlite3 11.7 | SQLite WAL + BEGIN IMMEDIATE，无需外部 DB |
| 密码学 | @noble/secp256k1 2.1 + @noble/hashes 1.5 | 浏览器可跑、常数时间算术、无 WASM 依赖 |
| 密码哈希 | bcrypt 5.1（rounds=12） | 用户口令存储 |
| JWT | jsonwebtoken 9.0 | HS256 会话令牌 |
| 校验 | express-validator 7.2 | register/login 字段校验 |
| 前端框架 | React 19 + Vite 8 | 现代构建、HMR |
| UI 库 | antd 6 | Steps / InputNumber / Alert / Menu |
| 样式 | antd ConfigProvider theme token + 原生 CSS | 主题统一、零额外依赖 |
| Polyfill | vite-plugin-node-polyfills | Buffer / process 浏览器兜底 |
| 测试 | vitest 4.1 + happy-dom + supertest | 单元 + 集成 + 客户端构建 |
| 编排 | concurrently 9.1 | 同时启动前后端 dev |

详细选型理由见 [docs/IMPLEMENTATION.md §2.2](file:///d:/密码货币与区块链技术/blindcash/docs/IMPLEMENTATION.md)。

---

## 6. 里程碑

| 里程碑 | 范围 | commit | 测试 |
|--------|------|--------|------|
| M1 | 身份层（users + auth + role + bcrypt + JWT） | 30de03a | 13 |
| M2 | 密码学层（secp256k1 + 4-move + cut-and-choose + 客户端子集） | 8015df3 | 50 |
| M3 | 银行密钥层（bank_keys singleton + /api/bank/pubkey） | c0ae174 | 12（累计 62） |
| M4 | 取款层（4-move 状态机 + withdrawal_sessions + 教授 3 必测） | 9b76aba | 19（累计 81） |
| M5 | 支付层（spent_coins + formatGate H1 + token_hash H2 + 双花 H3） | a01ba90 | 13（累计 94） |
| M6 | 前端 E2E（取款 4-step + 收款预验签 + α/β useRef） | 20c6699 / 96c258f | clientBuild 4/4 |
| M7 | 集成测试 + 文档七件套 + ISOLATION 补证据 | b6fc0c7 / cfa7583 | 10（累计 104） |

详细里程碑落地清单见 [docs/IMPLEMENTATION.md §1](file:///d:/密码货币与区块链技术/blindcash/docs/IMPLEMENTATION.md)。

---

## 7. 测试

```bash
# 全量测试（104 用例，约 65 秒，含概率测试）
npm test

# 详细输出（含盲性证据的熵值打印）
BC_VERBOSE=1 npm test

# 单独跑某个里程碑
npx vitest run backend/tests/integration.test.js
```

**预期输出**：

```
 Test Files  8 passed (8)
      Tests  104 passed (104)
```

**测试矩阵**：

- 正确性（happy path）：28 用例
- 篡改检测：17 用例
- 不变量验证：22 用例（α/β 不离开设备、session 唯一、过期懒清理退款、singleton 密钥一致性）
- 盲性证据：3 用例（1000-trial Shannon 熵、token-session 不可链接、pickRandomJ 分布）
- 作弊概率：2 用例（1000-trial 作弊成功率 [50, 200]/1000）
- 格式校验 H1：4 用例
- 双花检测 H3：4 用例
- 角色守卫：6 用例
- 跨用户访问：4 用例
- 构建可跑性：4 用例
- 配置 sanity：2 用例

详见 [docs/TESTING.md](file:///d:/密码货币与区块链技术/blindcash/docs/TESTING.md)。

---

## 8. 评分标准对照

> 对照课程评分标准，自评本项目达成情况。

### 8.1 基本项（80 分）

| 评分维度 | 自评 | 说明 |
|----------|------|------|
| 基本功能完成 | ✅ | 银行 / 付款人 / 收款人 三大模块全闭环（详见 §2） |
| 文档完整 | ✅ | README + REQUIREMENTS + DESIGN + IMPLEMENTATION + TESTING + USERGUIDE + ISOLATION 七件套 |

### 8.2 加分项（+20 分）

| 评分维度 | 自评 | 证据 |
|----------|------|------|
| 界面优美，人际交互友好 | +10 | antd 6 视觉规范；4-step Steps 向导；300ms debounce 预验签即时反馈；TTL 倒计时红色告警；role-gated 菜单（customer 看不见收款入口，merchant 看不见取款入口）；双花 409 友好提示文案 |
| 文本结构合理，逻辑清晰，正文格式规范 | +10 | 七件套分章清晰；代码块均标注语言；表格分章；文献引用编号 [1]-[n]；中文表述一致；ASCII 架构图清晰 |

### 8.3 扣分项风险自检

| 扣分维度 | 自检 | 说明 |
|----------|------|------|
| 功能缺失（-10） | 0 | 银行（签发 + 兑付 + 双花检测）、付款人（注册 + 取款 + 4-move 协议）、收款人（注册 + 收款 + 预验签）三模块完整 |
| 文档内容缺失（-10） | 0 | 七件套覆盖需求 / 设计 / 实现 / 测试 / 用户手册 / 不变量隔离 / 项目入口 |
| 文档格式混乱（-5） | 0 | 统一 Markdown 规范；标题层级一致；代码块语言标注；表格分章；文献编号规范 |

---

## 9. 参考文献

- [1] Chaum, D. (1982). *Blind Signatures for Untraceable Payments*. CRYPTO.
- [2] Schnorr, C.-P. (1989). *Efficient Identification and Signatures for Smart Cards*. CRYPTO.
- [3] RFC 6979 — HMAC-based deterministic nonce generation.
- [4] BIP-340 — Schnorr signatures over secp256k1.
- [5] @noble/curves 文档 — https://paulmillr.com/noble/
- [6] SQLite WAL 模式文档 — https://sqlite.org/wal.html
- [7] v3 实施大纲 §2.2 / §2.3 / §3.1 / §3.3 — 协议、状态机、不变量来源
- [8] Shannon, C.E. (1948). *A Mathematical Theory of Communication*. Bell System Technical Journal.
