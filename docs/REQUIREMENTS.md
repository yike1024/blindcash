# BlindCash 需求规格说明书（REQUIREMENTS）

> 项目：基于 Schnorr 盲签名的盲签名数字货币演示系统
> 范围：M1-M7 全部已交付功能
> 受众：答辩评委 / 后续维护者

---

## 0. 评分标准对照（三大功能模块）

> 对照课程评分标准"按银行、付款人、收款人三个大功能来看"。

| 大功能 | 子功能 | 实现位置 | 验收用例 |
|--------|--------|----------|----------|
| **银行** | 密钥对生成与持久化 | `bankKeyService.getOrGenerate` | `bankKeyService.test.js`（12 用例） |
| | 公钥公开接口 | `GET /api/bank/pubkey` | `bankKeyService.test.js` |
| | 4-move 协议银行侧（init/submit/reveal） | `withdrawalService` | `withdrawal.test.js`（19 用例） |
| | Cut-and-choose 验证 + pickRandomJ | `cutAndChoose.verifyRevealed` | `cutAndChoose.test.js`（18 用例） |
| | 双花检测（serial + token_hash） | `paymentService.processPayment` | `payment.test.js`（13 用例） |
| **付款人** | 注册 + 登录 + 初始余额 100 | `/api/auth/register` | `auth.test.js` + `integration.test.js` |
| | 取款 4-step 向导 | `Withdraw.jsx` + `/api/withdraw/*` | `withdrawal.test.js` |
| | α/β 内存隔离 + beforeunload 守卫 | `Withdraw.jsx` useRef | `withdrawal.test.js` 必测#1 |
| | 4-move 协议用户侧（blinding + unblind） | `blinding.js` | `blinding.test.js`（9 用例） |
| | TTL 倒计时 + cancel 流程 | `Withdraw.jsx` | `withdrawal.test.js` 必测#3 |
| **收款人** | 注册 + 登录 | `/api/auth/register`（角色互斥） | `auth.test.js` |
| | 收款页（粘贴 + 预验签 + 提交） | `Payment.jsx` + `/api/payment` | `payment.test.js` |
| | 预验签（client verifySig） | `schnorrBlindClient.verifySig` | `clientBuild.test.js`（4 用例） |
| | 双花 409 演示 | `Payment.jsx` "再次提交"按钮 | `payment.test.js` H3 |
| | 角色守卫（customer 越权 → 403） | `middleware/auth.js` | `payment.test.js` role guard |

**自评**：三大功能模块全闭环，无功能缺失（-10 分风险已规避）。

---

## 1. 项目目标

构建一个**教学用**的盲签名数字货币（BlindCash）系统，完整实现 Schnorr 盲签名的 cut-and-choose 4-move 协议，使顾客向银行取款时**银行无法链接取款行为与后续消费**，同时通过双花检测保证同一 token 不可重复花费。

**非目标**（明示排除）：
- 银行私钥的密钥管理（HSM / TEE / Shamir）—— 属于"密钥安全"独立维度（ISOLATION §五）
- 生产级性能优化、水平扩展、抗 DoS 加固
- 真实法币对接、KYC/AML 合规

---

## 2. 角色（Actor）

| 角色 | 权限 | 限制 |
|---|---|---|
| **顾客（customer）** | 注册自动获初始余额 100；发起 4-move 取款；取消未完成取款 | 不可收款（`/api/payment` → 403） |
| **商户（merchant）** | 接收 token 存款；本地预验签；触发双花演示 | 不可取款（`/api/withdraw/*` → 403）；初始余额 0 |
| **银行（bank）** | 持签名密钥对 `(x, P)`；4-move 中生成 `R_i` 与 `s_j`；维护 spent_coins | 服务器端进程，无独立 UI |
| **任何访客** | `GET /api/bank/pubkey` 拿银行公钥 `P` 做公开验签 | 仅此一个公开端点 |

---

## 3. 用例图（Use Case）

```
        ┌────────────────────────────────────────────────────┐
        │                  BlindCash 系统                    │
        │                                                    │
   ┌────┴────┐  注册/登录      ┌────────────────────┐        │
   │  顾客   │─────────────────▶│ 用户管理          │        │
   │         │  修改余额(只减) ┌▶│ (register/login)  │        │
   │         │  ┌──────────┐  │ └────────────────────┘        │
   │         │  │ 取款向导 │──┘                               │
   │         │  │ (4-move) │────────────────────┐             │
   │         │  └──────────┘                    ▼             │
   │         │                          ┌────────────────┐    │
   │         │                          │  4-move 取款   │    │
   │         │                          │  init/submit/  │    │
   │         │                          │  reveal/cancel │    │
   │         │                          └────────┬───────┘    │
   │         │                                   │            │
   │         │  复制 token 给商户                 ▼            │
   │         │ ─────────────────────────────────▶            │
   └─────────┘                          ┌────────────────┐    │
                                          │  支付/双花检测 │    │
   ┌─────────┐  注册/登录                  │  /api/payment  │    │
   │  商户   │─────────────────▶  ────────┘                │    │
   │         │  粘贴 token                                          │
   │         │  本地预验签(verifySig)                              │
   │         │  提交存款 → 余额 +                                  │
   │         │  再次提交同 token → 409 演示双花                    │
   └─────────┘                                                    │
                                                                  │
   ┌─────────┐   GET /api/bank/pubkey                             │
   │ 任何人  │───────────────────────────────────────────────────▶│
   │  (访客) │   公开验签 token 真伪                              │
   └─────────┘                                                    │
        └────────────────────────────────────────────────────────┘
```

---

## 4. 用例详表

### UC-1：顾客注册

| 项 | 内容 |
|---|---|
| 参与者 | 顾客 |
| 前置 | 用户名未被占用 |
| 主流程 | 输入 username + password + role='customer' → POST `/api/auth/register` → 201 `{ user: { id, username, role, balance: 100 }, token }` |
| 备选 | 用户名已占 → 409 `USERNAME_TAKEN`；密码不合规 → 400 `VALIDATION_ERROR` |
| 后置 | 顾客 balance=100（M5 `INITIAL_BALANCE_CUSTOMER`） |

### UC-2：顾客 4-move 取款

| 项 | 内容 |
|---|---|
| 参与者 | 顾客 |
| 前置 | 已登录 + 无 active session + balance ≥ amount |
| 主流程 | ① `/withdraw/init { amount }` → `{ session_id, R[], N }`<br>② 本地构造 N 候选（α/β 仅内存） → `/withdraw/submit { session_id, candidates }` → `{ j }`<br>③ 构造 revealed(i≠j) → `/withdraw/reveal { session_id, revealed }` → `{ s_j }`<br>④ 本地 unblind：`s' = (s_j + α_j) mod n` → token `{serial, amount, R_prime, s_prime}` |
| 备选 | 已有 active session → 409 `ACTIVE_SESSION_EXISTS`；余额不足 → 400 `INSUFFICIENT_BALANCE`；金额非正整数 → 400 `INVALID_AMOUNT`；TTL 过期 → 400 `SESSION_EXPIRED`（自动退款） |
| 后置 | session.status='committed'；customer.balance -= amount；token 在顾客内存（剪贴板） |

### UC-3：顾客取消取款

| 项 | 内容 |
|---|---|
| 参与者 | 顾客 |
| 前置 | session.status ∈ {pending, submitted} |
| 主流程 | POST `/withdraw/cancel { session_id }` → 200 `{ refunded, new_balance }` |
| 备选 | 已 committed → 400 `NOT_CANCELLABLE`；session 不属于本用户 → 404 `SESSION_NOT_FOUND` |
| 后置 | session.status='cancelled'；customer.balance += amount（退款） |

### UC-4：商户收款（首次存款）

| 项 | 内容 |
|---|---|
| 参与者 | 商户 |
| 前置 | 已登录 + 持有顾客给的 token |
| 主流程 | 粘贴 token JSON → 前端 `verifySig` 预验签显示 ✓ → POST `/api/payment` → 200 `{ deposited, new_balance }` |
| 备选 | token 字段格式错误 → 400 `MALFORMED_TOKEN`；签名验证失败 → 400 `SIGNATURE_INVALID`；token 已花费 → 409 `DOUBLE_SPEND` |
| 后置 | spent_coins 多 1 行；merchant.balance += amount |

### UC-5：商户双花演示

| 项 | 内容 |
|---|---|
| 参与者 | 商户 |
| 前置 | UC-4 已成功存款一次 |
| 主流程 | 在 Pay 页点"再次提交同一 token" → 409 `DOUBLE_SPEND` → UI 显示双花检测成功 |
| 教学要点 | 真实双花 = 两商户并发提交同 token，服务器 `BEGIN IMMEDIATE` 串行化；具体哪个 200 哪个 409 由调度决定，**不保证先发起者赢**（教授 M6.md #2） |

### UC-6：访客公开验签

| 项 | 内容 |
|---|---|
| 参与者 | 任何人（含未登录） |
| 前置 | 持有 token + 知道 bank pubkey |
| 主流程 | GET `/api/bank/pubkey` → 用 `verifySig(R', s', serial, amount, P)` 本地验证 `s'·G == R' + e'·P` |
| 后置 | 无（只读操作） |
| 教学要点 | 体现盲签名的 **public-verifiability**：任何人可验证，但不可链接到取款者 |

---

## 5. 功能需求（FR）

| ID | 需求 | 实现里程碑 |
|---|---|---|
| FR-1 | 用户注册/登录，role ∈ {customer, merchant} 不可改 | M1 |
| FR-2 | 顾客注册自动获初始余额 100 | M5 |
| FR-3 | 银行启动生成并保存签名密钥对 `(x, P)`，单例 row | M3 |
| FR-4 | 公开端点 `GET /api/bank/pubkey` 返回 33B 压缩 P | M3 |
| FR-5 | Schnorr 盲签 4-move 协议：init / submit / reveal / cancel | M2 + M4 |
| FR-6 | cut-and-choose N=100（演示可改 BC_DEMO_N=10）| M2 |
| FR-7 | submit payload 含 α/β → 400 `BLINDER_LEAKED` | M4 |
| FR-8 | reveal 含 j 索引 → 400 `SIGNED_CANDIDATE_REVEALED` | M4 |
| FR-9 | 每用户最多 1 个 active session（DB UNIQUE 索引兜底）| M4 |
| FR-10 | TTL 过期懒清理：next init 触发旧 session 退款 | M4 |
| FR-11 | 商户收款：`verifySig` 在事务外 → `BEGIN IMMEDIATE` 原子三连 | M5 |
| FR-12 | 双花检测：serial PRIMARY KEY + token_hash UNIQUE | M5 |
| FR-13 | 顾客取款向导（4-step + α/β 内存 + TTL 倒计时 + cancel + 复制 token）| M6 step1 |
| FR-14 | 商户收款页（粘贴 token → 本地预验签 ✓ → 提交 → 双花 409 演示）| M6 step2 |
| FR-15 | 端到端集成测试覆盖 E2E + 跨用户 + 跨商户并发双花 + 过期懒清理 | M7 step1 |

---

## 6. 非功能需求（NFR）

| ID | 需求 | 满足方式 |
|---|---|---|
| NFR-1 | **盲性（Unlinkability）**：银行无法将 token 兑付链接回取款者 | α_j/β_j 永不出本机；cut-and-choose N=100 → 1% 作弊概率；1000-trial 熵测试 ≥ 200 bits |
| NFR-2 | **不可伪造性**：顾客无法伪造 token | s'·G == R' + e'·P 验签 + Schnorr 离散对数安全假设 |
| NFR-3 | **双花不可重放**：同一 token 第二次提交必失败 | `spent_coins.serial PRIMARY KEY` + `BEGIN IMMEDIATE` 串行化 |
| NFR-4 | **公私钥隔离**：浏览器只持公钥 P，私钥 x 永不离开服务器 | `crypto/client/` 子集（M2 happy-dom 验证）|
| NFR-5 | **服务器事务原子性**：余额变动 + 双花写入要么全成要么全败 | `runImmediateTx` + `BEGIN IMMEDIATE` |
| NFR-6 | **跨标签会话隔离**：customer / merchant 两标签同时登录互不干扰 | `sessionStorage` per-tab 缓存 token+user |
| NFR-7 | **公开可验证**：任何访客都能用 P 验证 token 真伪 | `GET /api/bank/pubkey` 无 auth |
| NFR-8 | **测试覆盖**：核心协议 + 双花 + 跨用户 + 盲性证据全覆盖 | 104/104 通过（8 文件）|
| NFR-9 | **前端构建 0 错误**：vite build + oxlint 双 0 | M6 step1/step2 验证 |
| NFR-10 | **教学可读性**：代码注释解释"为什么"而非"是什么" | 每个关键文件头部 comment block |

---

## 7. 约束与假设

### 约束
- 后端：Node.js 24 + Express + better-sqlite3（WAL 模式）
- 前端：React 19 + Vite 8 + antd 6 + Tailwind
- 密码学：@noble/secp256k1 + @noble/hashes（secp256k1 曲线）
- 端口：backend 4100 / frontend 5174（与 cryptobank 项目并行不冲突）

### 假设
1. 银行签名密钥不泄露（密钥管理是独立维度，ISOLATION §五）
2. 浏览器进程隔离可信（α/β 内存安全详见 IMPLEMENTATION.md §风险#3）
3. SQLite 单机事务正确性（不涉及分布式一致性）
4. 攻击者不能在顾客设备上注入恶意 JS（XSS 防护是另一维度）

---

## 8. 验收准则

| 准则 | 验证方式 |
|---|---|
| 顾客取款后银行无法链接到 token | M2 1000-trial 熵测试 ≥ 200 bits |
| 伪造 token 必被验签拒绝 | M5 `SIGNATURE_INVALID` 测试 |
| 同 token 重复提交必失败 | M5 + M7 `DOUBLE_SPEND` 测试 |
| 跨用户 session 隔离 | M7 `SESSION_NOT_FOUND` 测试 |
| 全量测试 0 失败 | `npm test` → 104/104 |
| 前端 build 0 错误 | `cd frontend && npx vite build` exit 0 |
| 浏览器完整 E2E 跑通 | 教授 M6.md #5 路径：register → withdraw → 复制 → 粘贴 → 预验签 → 提交 → 重试 409 |
