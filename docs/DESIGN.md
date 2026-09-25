# BlindCash 设计文档（DESIGN）

> 内容：系统架构 / 4-move 协议时序 / ER 图 / API 表 / 关键算法
> 关联：[REQUIREMENTS.md](./REQUIREMENTS.md) | [IMPLEMENTATION.md](./IMPLEMENTATION.md) | [ISOLATION.md](../ISOLATION.md)

---

## 1. 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        浏览器（前端）                            │
│  React 19 + Vite 8 + antd 6                                     │
│  ┌────────────────┐  ┌────────────────┐  ┌───────────────────┐  │
│  │ /register      │  │ /withdraw      │  │ /payment          │  │
│  │ /login         │  │ 4-step Steps   │  │ 粘贴token→预验签  │  │
│  │ /dashboard     │  │ α/β useRef     │  │ →POST /payment    │  │
│  │ /bank /wallet  │  │ TTL 倒计时     │  │ →双花 409 演示    │  │
│  │ /history /privacy│ │                │  │ →escrow 托管     │  │
│  └────────────────┘  └────────────────┘  └───────────────────┘  │
│           │                    │                    │            │
│           └────────────────────┴────────────────────┘            │
│                              │                                  │
│              sessionStorage（token + user, per-tab）             │
│                              │                                  │
│              crypto/client/ (浏览器可跑子集)                       │
│              ┌────────────────────────────────────────────┐      │
│              │ blinding.js       generateBlinders          │      │
│              │                   computeBlindedCommitment│      │
│              │                   unblindResponse          │      │
│              │ schnorrBlindClient.js  verifySig (预验签)    │      │
│              │ pointFormat.js    isValidCompressedFormat  │      │
│              └────────────────────────────────────────────┘      │
└─────────────────────────────┬───────────────────────────────────┘
                              │ HTTPS /api/* (Vite proxy 5174→4100)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Node.js 24 后端（Express）                     │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  路由层 (routes/)                                         │    │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────┐ │    │
│  │  │ auth.js │ │ bank.js  │ │ withdrawal.js│ │ payment  │ │    │
│  │  │ register│ │ /pubkey  │ │ init/submit/│ │ /api/     │ │    │
│  │  │ login   │ │ (no auth)│ │ reveal/cancel│ │ payment  │ │    │
│  │  └─────────┘ └──────────┘ └──────────────┘ └──────────┘ │    │
│  └──────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  中间件                                                   │    │
│  │  authenticateJWT (Bearer) + requireRole('customer'/'merchant')│   │
│  └──────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  服务层 (services/)                                       │    │
│  │  authService     bcrypt(12) + JWT                         │    │
│  │  userService     createUser (balance=0, Phase 1 自助充值)│    │
│  │  bankKeyService  getOrGenerate (singleton keypair)        │    │
│  │  withdrawalService  4-move state machine + 退款事务      │    │
│  │  paymentService     formatGate + verifySig + atomic deposit│  │
│  └──────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  密码学层 (crypto/)                                       │    │
│  │  server/  curve.js  G,n,modN,Point,scalarToBytes         │    │
│  │           hashToScalar.js  H(tag‖R'‖serial‖amount‖P) mod n│   │
│  │           schnorrBlind.js  bankStep1/3, verifySig, keypair│    │
│  │           cutAndChoose.js  verifyRevealed, pickRandomJ   │    │
│  │  client/  blinding.js         (browser-safe subset)       │    │
│  │           schnorrBlindClient.js (verifySig mirror)        │    │
│  │           pointFormat.js      (33B format check only)     │    │
│  └──────────────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │  数据层 (models/db.js + schema.sql)                      │    │
│  │  PostgreSQL + pg 连接池 (migrations/*.sql)                │    │
│  │  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌────────┐  │    │
│  │  │ users    │ │ bank_keys    │ │ withdraw_│ │ spent_ │  │    │
│  │  │          │ │ (singleton)  │ │ sessions │ │ coins  │  │    │
│  │  └──────────┘ └──────────────┘ └──────────┘ └────────┘  │    │
│  │  runImmediateTx (单连接事务 + UNIQUE 约束串行化)            │    │
│  └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. 4-move 协议时序图（cut-and-choose）

```
顾客(浏览器)                       银行(后端)                       商户(浏览器)
    │                                  │                                  │
    │  GET /api/bank/pubkey            │                                  │
    │─────────────────────────────────▶│                                  │
    │  { public_key: P (33B hex) }    │                                  │
    │◀─────────────────────────────────│                                  │
    │                                  │                                  │
    │  for i in 0..N-1 (本地预生成):    │                                  │
    │   α_i, β_i ← randomScalar()      │                                  │
    │   serial_i ← 32 random bytes     │                                  │
    │  (此刻 N 个 α/β/serial 都在内存)  │                                  │
    │                                  │                                  │
    │  ① POST /api/withdraw/init       │                                  │
    │     { amount: 30 }                │                                  │
    │─────────────────────────────────▶│                                  │
    │                                  │  lazyCleanupExpiredSessions     │
    │                                  │  事务 (BEGIN):                │
    │                                  │   拒绝若已有 active session     │
    │                                  │   拒绝若 balance < amount        │
    │                                  │   UPDATE users SET balance -= 30│
    │                                  │   生成 N 个新鲜 k_i              │
    │                                  │   R_i = k_i · G                  │
    │                                  │   INSERT session(pending, +5min)│
    │                                  │  COMMIT                          │
    │  { session_id, R: [N×hex66],     │                                  │
    │    amount, N, ttl_ms }           │                                  │
    │◀─────────────────────────────────│                                  │
    │                                  │                                  │
    │  for i in 0..N-1:                 │                                  │
    │   R'_i = R_i + α_i·G + β_i·P     │                                  │
    │   e'_i = H(tag‖R'_i‖serial_i‖30‖P) mod n                          │
    │   e_i  = (e'_i + β_i) mod n       │                                  │
    │   candidates[i] = { e_i, R'_i,    │                                  │
    │                     serial_i }    │                                  │
    │   ⚠ 不含 α_i/β_i！                │                                  │
    │                                  │                                  │
    │  ③ POST /api/withdraw/submit     │                                  │
    │     { session_id, candidates[N] } │                                  │
    │─────────────────────────────────▶│                                  │
    │                                  │  API 防御:                       │
    │                                  │   若 candidate 含 alpha/beta    │
    │                                  │   → 400 BLINDER_LEAKED          │
    │                                  │  事务 (BEGIN):                │
    │                                  │   检查 session 状态/过期         │
    │                                  │   合并 e/R'/serial 进 candidates│
    │                                  │   j ← pickRandomJ(N)             │
    │                                  │   UPDATE session(submitted, j)  │
    │                                  │  COMMIT                          │
    │  { j: 银行随机选中的索引 }       │                                  │
    │◀─────────────────────────────────│                                  │
    │                                  │                                  │
    │  构造 revealed = [{i, α_i, β_i}  │                                  │
    │                   for i ≠ j]      │                                  │
    │  (revealed 恰 N-1 个, 不含 j)    │                                  │
    │                                  │                                  │
    │  ⑤ POST /api/withdraw/reveal     │                                  │
    │     { session_id, revealed[N-1] } │                                  │
    │─────────────────────────────────▶│                                  │
    │                                  │  API 防御:                       │
    │                                  │   若 revealed 含 i===j           │
    │                                  │   → 400 SIGNED_CANDIDATE_REVEALED│
    │                                  │  事务 (BEGIN):                │
    │                                  │   for each (i, α_i, β_i) in     │
    │                                  │     revealed (i≠j):             │
    │                                  │     verifyRevealed(R_i, R'_i,    │
    │                                  │       serial_i, amount, P,       │
    │                                  │       α_i, β_i, e_i)             │
    │                                  │     任一失败 → refund + abort   │
    │                                  │     → 400 CUT_AND_CHOOSE_FAILED │
    │                                  │   s_j = (k_j + e_j · x) mod n   │
    │                                  │   UPDATE session(committed)     │
    │                                  │  COMMIT                          │
    │  { s_j: hex64 }                  │                                  │
    │◀─────────────────────────────────│                                  │
    │                                  │                                  │
    │  本地 unblind:                    │                                  │
    │   s' = (s_j + α_j) mod n          │                                  │
    │   ⚠ 丢弃 α_j, β_j (使命完成)     │                                  │
    │   token = { serial_j, amount=30, │                                  │
    │             R'_j, s' }            │                                  │
    │   验证 s'·G == R'_j + e'_j · P    │                                  │
    │                                  │                                  │
    │  (剪贴板复制 token JSON)           │                                  │
    │                                  │                                  │
    │  ─ ─ ─ ─ ─ ─ 离线交付 token ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
    │                                  │                                  │
    │                                  │  本地预验签:                      │
    │                                  │   e' = H(tag‖R'‖serial‖30‖P)     │
    │                                  │   s'·G == R' + e'·P ?             │
    │                                  │  ✓ 通过 → 启用「提交存款」       │
    │                                  │                                  │
    │                                  │  POST /api/payment                │
    │                                  │   { serial, amount, R_prime,     │
    │                                  │     s_prime }                    │
    │                                  │◀─────────────────────────────────│
    │                                  │  formatGate (H1):                │
    │                                  │   serial 64hex / R' 66hex 02|03  │
    │                                  │   s' 64hex scalar∈[1,n-1]        │
    │                                  │   amount 正整数                  │
    │                                  │  verifySig(R', s', serial,       │
    │                                  │   amount, P) (事务外)            │
    │                                  │   失败 → 400 SIGNATURE_INVALID  │
    │                                  │  token_hash = SHA256(serial‖R'‖s')│
    │                                  │  事务 (BEGIN):                │
    │                                  │   SELECT serial FROM spent_coins │
    │                                  │   存在 → 409 DOUBLE_SPEND       │
    │                                  │   INSERT spent_coins(serial,    │
    │                                  │     amount, deposited_to,        │
    │                                  │     token_hash)                 │
    │                                  │   UPDATE merchant.balance += 30 │
    │                                  │  COMMIT                          │
    │                                  │  { deposited: 30,               │
    │                                  │    new_balance: 30 }            │
    │                                  │─────────────────────────────────▶│
    │                                  │                                  │
    │                                  │                                  │ 再次提交同一 token
    │                                  │                                  │  (演示双花)
    │                                  │  POST /api/payment (同上)         │
    │                                  │◀─────────────────────────────────│
    │                                  │  formatGate ✓                    │
    │                                  │  verifySig ✓                    │
    │                                  │  事务 (BEGIN):                │
    │                                  │   SELECT serial → 已存在        │
    │                                  │   → 409 DOUBLE_SPEND            │
    │                                  │  (transaction 回滚, 不二次扣款) │
    │                                  │─────────────────────────────────▶│
    │                                  │                                  │ 显示"双花检测成功"
```

**正确性证明**（v3 §2.2）：
```
s'·G = (s + α)·G = (k + e·x + α)·G = R + α·G + e·x·G
     = R + α·G + (e' + β)·x·G = R + α·G + β·P + e'·P
     = (R + α·G + β·P) + e'·P = R' + e'·P  ✓
```

---

## 3. ER 图（数据库表关系）

```
┌─────────────────────────┐
│  users                  │
├─────────────────────────┤
│  id            PK int   │
│  username      UNIQUE   │
│  password_hash (bcrypt) │
│  role          CHECK    │
│  │             ('cust' │
│  │              'mer') │
│  balance       int     │
│  created_at    datetime│
└─────────┬───────────────┘
          │
          │ 1
          │
          │ N (FK customer_id)
          ▼
┌─────────────────────────┐        ┌─────────────────────────┐
│  withdrawal_sessions    │        │  bank_keys               │
├─────────────────────────┤        ├─────────────────────────┤
│  id            PK UUID │        │  id            PK int   │
│  customer_id  FK→users │        │  public_key   BYTEA(33) │
│  amount        int     │        │  private_key  BYTEA(32) │
│  n_candidates  int     │        │  created_at   datetime │
│  candidates    JSON     │        │  CHECK(id=1)            │
│  (no α_i/β_i!)         │        │  (singleton)            │
│  j_index       int?    │        └─────────────────────────┘
│  status        CHECK   │
│  created_at   datetime│        ┌─────────────────────────┐
│  expires_at   datetime│        │  spent_coins            │
└─────────────────────────┘        ├─────────────────────────┤
   UNIQUE INDEX:                  │  serial       PK BYTEA(32)│
   idx_ws_active_per_customer     │  amount       int       │
   ON customer_id                 │  deposited_to FK→users  │
   WHERE status IN                │  token_hash   BYTEA(32) │
     ('pending','submitted')     │  spent_at     datetime  │
                                  └─────────────────────────┘
                                   UNIQUE INDEX:
                                   idx_sc_token_hash
                                   ON token_hash
```

**关键约束**（schema.sql）：
- `users.role` CHECK ∈ {customer, merchant}（不可改）
- `bank_keys.id = 1` CHECK（singleton）
- `withdrawal_sessions.status` CHECK ∈ 6 状态
- `idx_ws_active_per_customer` partial UNIQUE：每用户最多 1 个 active session（pending|submitted）
- `spent_coins.serial` PRIMARY KEY：双花检测主防线
- `idx_sc_token_hash` UNIQUE：bytes 级 token_hash 兜底防 re-casing 攻击

---

## 4. API 表

### 4.1 认证

| 方法 | 路径 | 鉴权 | 请求 | 成功响应 | 错误 |
|---|---|---|---|---|---|
| POST | `/api/auth/register` | 无 | `{ username, password, role }` | 201 `{ user: { id, username, role, balance }, token }` | 400 `VALIDATION_ERROR`；409 `USERNAME_TAKEN` |
| POST | `/api/auth/login` | 无 | `{ username, password }` | 200 同上 | 400 `VALIDATION_ERROR`；401 `INVALID_CREDENTIALS` |

**密码规则**：≥8 位 + 字母 + 数字 + 特殊字符（`/[^a-zA-Z]/`、`/[^0-9]/`、`/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`!]/`）

### 4.2 银行公钥

| 方法 | 路径 | 鉴权 | 响应 |
|---|---|---|---|
| GET | `/api/bank/pubkey` | 无 | 200 `{ public_key: "hex66" }`（33B 压缩 P） |

### 4.3 取款 4-move（customer-only）

| 方法 | 路径 | 请求 | 成功 | 失败 |
|---|---|---|---|---|
| POST | `/api/withdraw/init` | `{ amount }` | 201 `{ session_id, R: [hex66×N], amount, N, ttl_ms }` | 400 `INVALID_AMOUNT` / `INSUFFICIENT_BALANCE`；409 `ACTIVE_SESSION_EXISTS` |
| POST | `/api/withdraw/submit` | `{ session_id, candidates: [{ e:hex64, R_prime:hex66, serial:hex64 }×N] }` | 200 `{ j }` | 400 `BLINDER_LEAKED` / `INVALID_CANDIDATE` / `CANDIDATE_COUNT` / `SESSION_EXPIRED`；404 `SESSION_NOT_FOUND`；409 `WRONG_STATUS` |
| POST | `/api/withdraw/reveal` | `{ session_id, revealed: [{ i, alpha:hex64, beta:hex64 }×N-1] }` | 200 `{ s_j: hex64 }` | 400 `SIGNED_CANDIDATE_REVEALED` / `REVEAL_COUNT` / `REVEAL_DUPLICATE` / `REVEAL_INCOMPLETE` / `CUT_AND_CHOOSE_FAILED` / `SESSION_EXPIRED` |
| POST | `/api/withdraw/cancel` | `{ session_id }` | 200 `{ refunded, new_balance }` | 400 `NOT_CANCELLABLE`；404 `SESSION_NOT_FOUND` |

### 4.4 支付（merchant-only）

| 方法 | 路径 | 请求 | 成功 | 失败 |
|---|---|---|---|---|
| POST | `/api/payment` | `{ serial:hex64, amount, R_prime:hex66, s_prime:hex64 }` | 200 `{ deposited, new_balance }` | 400 `MALFORMED_TOKEN` / `SIGNATURE_INVALID`；409 `DOUBLE_SPEND` |

### 4.5 健康

| 方法 | 路径 | 响应 |
|---|---|---|
| GET | `/api/health` | 200 `{ status: 'ok', service: 'blindcash-backend', milestone: 'M5' }` |

---

## 5. 状态机（withdrawal_session.status）

```
                  ┌────────────┐
                  │  (none)    │
                  └─────┬──────┘
                        │ POST /init (debit balance)
                        ▼
                  ┌────────────┐
        ┌────────▶│  pending   │◀──┐
        │         └─────┬──────┘   │
        │               │           │
        │   ┌───────────┼───────────┼───────────┐
        │   │ POST      │ POST     │ POST      │ TTL elapse +
        │   │ /cancel   │ /submit  │ /submit   │ next /init
        │   │ (refund)  │ (pick j) │ on expired│ (lazy refund)
        │   ▼           ▼          ▼           ▼
        │ ┌────────┐  ┌──────────┐  ┌────────┐  ┌────────┐
        │ │cancelled│  │submitted │  │expired │  │expired │
        │ └────────┘  └─────┬────┘  └────────┘  └────────┘
        │                   │
        │   ┌───────────────┼───────────────┐
        │   │ POST          │ POST          │ TTL elapse
        │   │ /cancel       │ /reveal       │ + next /init
        │   │ (refund)      │ (verify       │ (lazy refund)
        │   ▼               │  cut-&-choose)│
        │ ┌────────┐         │               ▼
        │ │cancelled│         │        ┌────────┐
        │ └────────┘         │        │expired │
        │                    │        └────────┘
        │                    │ verify FAIL → refund
        │                    ▼
        │              ┌──────────┐
        │              │ aborted  │
        │              └──────────┘
        │                    │ verify PASS → s_j returned
        │                    ▼
        │              ┌──────────┐
        │              │committed │  (terminal success)
        │              └──────────┘
        │
        └──── (any non-committed state can be cleaned up by next /init if TTL elapsed)
```

**Terminal 状态**：`committed` / `aborted` / `cancelled` / `expired` 都不可再操作。

---

## 6. 关键算法说明

### 6.1 hashToScalar（域分离 + canonical 编码）

```
tag_bytes  = utf8("blindcash-v1")
canon      = R'(33B) ‖ serial(32B) ‖ amount(8B BE) ‖ P(33B)
input     = tag_bytes ‖ canon
e'        = (SHA256(input) mod n) || 1   // 防 0 退化
```

**为什么固定长度**：R'/serial/P 都长度固定（33/32/33 字节），不需要 length prefix，拼接无歧义。

**为什么域分离 tag**：防止跨协议签名重放（同一 (R', serial, amount) 在不同 tag 下产生不同 e'）。

### 6.2 cut-and-choose verifyRevealed

对每个 i ≠ j：
1. 用顾客提交的 (α_i, β_i) 重新计算 `R'_recompute = R_i + α_i·G + β_i·P`
2. 与顾客在 submit 阶段提交的 `R'_i` 字节比对
3. 用 (α_i, β_i) 重新计算 `e_recompute = (H(tag‖R'_i‖serial_i‖amount‖P) + β_i) mod n`
4. 与 submit 阶段提交的 `e_i` 比对

任一不匹配 → cut-and-choose 失败 → refund + abort。

**作弊概率**：顾客伪造 1 个候选不被发现的概率 = 1/N。N=100 → 1% 作弊概率。1000-trial 熵测试已实证（M2）。

### 6.3 token_hash = SHA256(serial ‖ R' ‖ s')（H2 bytes 级）

**为什么 bytes 不 hex**：hex 编码有大小写歧义（0x0A vs 0x0a），若 hash hex 字符串，攻击者可改大小写产生不同 token_hash 绕过 UNIQUE 索引。hash 原始 bytes 完全消除该攻击面。

### 6.4 事务 + UNIQUE 约束串行化

`runImmediateTx` 在 PostgreSQL 上单连接执行 `BEGIN` → 写动作 → `COMMIT`，双花防护依赖 `spent_coins.serial` 的 UNIQUE 约束：
- SELECT serial → 已存在抛 409
- INSERT spent_coins（并发同 serial 触发 SQLSTATE 23505 → 409）
- UPDATE merchant.balance

任一步失败整体回滚。这保证双花并发场景下两个并发 payment 只能一个成功。

---

## 7. 前后端密码学边界（v3 风险 §一-1）

| 模块 | 服务器 | 浏览器 |
|---|---|---|
| `Point` 类（@noble/secp256k1） | ✅ crypto/server/curve.js | ✅ 经 vite-plugin-node-polyfills shim 后可用 |
| `crypto.getRandomValues` (Web Crypto) | ✅ Node 24 globalThis.crypto | ✅ 浏览器原生 |
| `randomScalar` (Node crypto) | ✅ utils.randomPrivateKey() | ❌ 不可用 → 用 Web Crypto in blinding.js |
| `verifySig`（完整 on-curve 检查） | ✅ crypto/server/schnorrBlind.js | 仅格式预检：crypto/client/pointFormat.js |
| `hashToScalar` (sha256) | ✅ @noble/hashes/sha256 | ✅ 同库浏览器可用 |
| `Buffer` / `process` | ✅ Node 原生 | ✅ polyfill shim |
| `bank_keys.private_key` | ✅ 服务器 DB | ❌ 永不出服务器 |

M2 `clientBuild.test.js` 在 happy-dom 下端到端跑 `generateBlinders + userComputeChallenge + verifySig` 实证浏览器子集可跑。

---

## 8. 前端路由与访问控制

| 路径 | 组件 | 访问控制 |
|---|---|---|
| `/register` | RegisterPage | 公开 |
| `/login` | LoginPage | 公开 |
| `/dashboard` | DashboardPage | 已登录 |
| `/bank` | BankPage | 已登录（充值 / 退币） |
| `/wallet` | WalletPage | 已登录（IndexedDB 钱包 + 托管管理） |
| `/withdraw` | WithdrawPage | 已登录（M7 角色解锁） |
| `/payment` | PaymentPage | 已登录（M7 角色解锁） |
| `/history` | HistoryPage | 已登录（账本流水） |
| `/privacy` | PrivacyPage | 已登录（匿名集分析） |

M7 起取款 / 收款对任何登录用户开放（不再按 customer/merchant 分区）；未登录访问受保护路由 → 重定向 `/login`。`admin` 专有接口仅在服务端由 `requireRole('admin')` 守卫，无对应前端页面。

---

## 9. 客户端钱包 XSS 威胁模型（Phase 2 m6 修正）

### 9.1 钱包存储位置

Phase 2 采用**方案 A**：钱包完全在客户端 IndexedDB，后端**无 wallet 表**、**无 /api/wallet/\*** 接口。银行对钱包内容完全无感知——这是 Chaum 式匿名性的关键（银行不能关联 serial → 用户身份）。

### 9.2 XSS 风险

IndexedDB **无加密**，token 以明文形式存储在浏览器中。如果应用存在 XSS 漏洞，攻击者可：

1. 通过 `indexedDB.open('blindcash-wallet')` 读取所有 token
2. 将 token 批量提交到攻击者控制的商户地址，一锅端用户所有电子现金

### 9.3 本系统的威胁面评估

| 因素 | 评估 |
|---|---|
| 攻击面 | 教学系统，无外部用户、无第三方脚本、无广告网络 |
| CSP | 未设置严格 CSP（Vite dev 模式 + antd 内联样式） |
| 输入处理 | React 默认转义，token JSON 走 `JSON.parse` 非 `innerHTML` |
| 第三方依赖 | antd / axios / @noble / idb / qrcode / jsqr — 均为知名库 |

**结论**：教学系统可接受。但必须诚实标注此限制——不能假装"钱包安全"。

### 9.4 生产环境应采取的措施

1. **加密存储**：用 WebCrypto API 派生密钥（PBKDF2 + 用户口令或设备绑定密钥），对 token 的 `serial`/`R_prime`/`s_prime` 字段做 AES-GCM 加密后再存 IndexedDB
2. **严格 CSP**：`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`（antd 需要 unsafe-inline 样式）
3. **Token 隔离**：每个 token 单独加密，密钥派生时混入 serial，减少一锅端风险
4. **自动过期**：钱包 token 设置 TTL，超时自动清除（需权衡用户体验）

### 9.5 为什么不加密也要存 IndexedDB 而不是 sessionStorage

sessionStorage 关标签页即丢失——token 直接消失，用户钱没了。IndexedDB 持久化是"功能正确性"的底线，加密是"安全增强"。教学系统选了"功能正确 + 诚实标注"的折中。

---

## 10. 银行私钥 at-rest 加密与密钥轮换（Phase 3）

### 10.1 AES-256-GCM at-rest 加密——威胁模型与诚实边界

Phase 3 在 `bank_keys.private_key` 列上落地了 AES-256-GCM at-rest 加密。**DB 中的私钥不再是 32 字节明文，而是 60 字节密文**（`nonce[12] + ciphertext[32] + tag[16]`），由 `BC_MASTER_KEY`（32-byte hex 字符串）加密 [1][2]。

**这个加密实际防什么 / 不防什么——必须诚实标注**：

| 威胁 | 是否防御 | 说明 |
|---|---|---|
| 数据库备份/数据文件泄露 | ✅ 防 | 没有 `BC_MASTER_KEY` 的攻击者拿到 PostgreSQL 备份只能看到密文，无法重建私钥 |
| 服务器进程被攻破（RCE / 内存 dump） | ❌ **不防** | 进程运行时 `MASTER_KEY` 必然在内存明文（`Buffer.from(MASTER_KEY, 'hex')`），且解密后的私钥也在 `bankKeyService._activeCache` 中。攻击者可以直接读内存拿到明文私钥 |
| 主机管理员 / DBA 恶意 | ⚠️ 部分防 | 防"只拿 DB 文件"的 DBA，不防"既能拿 DB 又能读 env / proc 内存"的 root |
| 内核级攻击 / 硬件攻击 | ❌ 不防 | 超出本系统威胁模型 |
| 真实 HSM（hardware security module） | ❌ 未实现 | 真实 HSM 的语义是"签名动作发生在硬件内部，私钥永不出设备" [3]。本系统的 `getPrivateKey()` 在进程内存中返回明文 x——这不是 HSM |

**结论（必须写在前面）**：本系统**没有实现 HSM**，AES-256-GCM 加密**只防 DB 文件静默泄露这一种场景**。教学系统的威胁模型假设服务器进程不被攻破——如果进程被控，所有防御在 `getPrivateKey()` 返回明文的那一刻就归零。

### 10.2 BC_MASTER_KEY 格式与生命周期

- **格式**：32-byte hex 字符串（64 字符），不是 passphrase→KDF——避免 KDF rounds 引入的启动延迟与"passphrase 弱"问题 [2]
- **来源**：环境变量 `BC_MASTER_KEY`（生产：CI secrets / K8s secret 注入；测试：未设时生成 ephemeral key 并 logger.warn）
- **生命周期**：进程启动时读一次，常驻 `_masterKeyBuf`；轮换 MASTER_KEY 需重加密整张 `bank_keys` 表（本系统未实现此工具—— MASTER_KEY 轮换是运维操作，密钥轮换是协议操作，二者不同维度）

### 10.3 密钥轮换（rotateKey）——协议层操作

Phase 3 实现了**密钥轮换**：管理员调用 `POST /api/admin/rotate-key` 后：

1. 当前 `status='active'` 的密钥标 `status='retired'`，写 `retired_at=now`、`retired_until=now+90d`
2. 生成新 keypair，AES-GCM 加密私钥，`INSERT` 一行 `key_version=旧+1, status='active'`
3. 清空 `_activeCache` + 删除旧 key_version 的 `_versionCache` 条目

**90 天宽限期**（v5 §三 3.2）：旧 token 拿 `key_id=旧 key_version` 调 `getPublicKeyByVersion(v)` 仍能查到旧公钥做验签；过了 `retired_until` 后调用 → `BankKeyError(403, 'KEY_RETIRED')`——银行不再兑付过期 token。这避免了"银行永久保留所有历史私钥"的反模式 [4]。

### 10.4 M3 分层修正——crypto 层不碰 DB

`verifySig({R_prime, s_prime, e_prime, publicKey, serial, amount})` 的**函数签名 Phase 3 未变**。这是 v5 §三 3.2 M3 修正的核心：crypto 层是纯函数，**不查 DB、不知道 key_id**。`paymentService` 负责从 `token.key_id` 解析出 `publicKey`（调 `getPublicKeyByVersion(key_id)`），再把 publicKey 传给 `verifySig` [5]。

这样 crypto 层可独立单测（`schnorrBlind.test.js` 19 个测试全过），而 DB / 多密钥 lookup 的复杂性留在 service 层（`bankKeyService.test.js` + `admin.test.js` 覆盖）。

### 10.5 审计日志（audit_log）——动作全集

Phase 3 引入 `audit_log` 表（`004_audit_log.sql`），`auditService.logAction` 在所有关键操作路径写入：

| action | 触发点 | 写入事务 |
|---|---|---|
| `deposit` | `bankService.deposit` | 调用方事务内（成功才留痕） |
| `withdraw` | `withdrawalService.initWithdrawal` | 调用方事务内 |
| `payment` | `paymentService.processPayment` | 调用方事务内 |
| `redeem` | `bankService.redeem`（v2 token） | 调用方事务内 |
| `key_rotate` | `bankKeyService.rotateKey`（admin 路由） | 独立事务（rotateKey 不在 tx 内） |
| `cancel` | `withdrawalService.cancelSession` | 调用方事务内 |
| `expire` | `withdrawalService.refundAndClose(...,'expired')` | 调用方事务内 |
| `invariant_violation` | `bankReserveService.runInvariantCheckedTx` catch 块 | **事务外**——失败事务已回滚，日志写在 catch 块的独立隐式事务中 |

**`invariant_violation` 的写入路径特殊**：事务已经回滚，所以 `runInvariantCheckedTx` 在 catch 块中（事务外）调 `logAction`，让 `auditService` 用自己的隐式事务写入。这保证"即使整笔交易回滚，违反不变量的行为也被记录"——是 M1 缺陷修复的关键部分 [6]。

### 10.6 文献参考

- [1] NIST SP 800-38D · §5.2.1.2 — AES-GCM 的 nonce 长度建议为 96 bit（本系统用 12 byte 随机 nonce，与建议一致）
- [2] NIST SP 800-132 · §4.1 — passphrase→KDF 的密钥派生模型；本系统采用直接 hex 密钥避免 KDF rounds 延迟
- [3] NIST SP 800-57rev5 · §5.3 — HSM 的"密钥永不出设备"语义
- [4] NIST SP 800-57rev5 · §8.3.4 — "cryptoperiod" 概念，过期密钥进入 "deactivated" 状态而非永久保留
- [5] OWASP ASVS L1 v4.0.31 §2.10 — "verify that signature verification is performed in a separate component from signature creation"，本系统的 crypto 层 / service 层分层即此原则
- [6] NIST SP 800-92rev1 · §3 — 审计日志应记录"安全相关事件"的成败两面，invariant_violation 是失败面的关键事件
