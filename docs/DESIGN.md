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
│  │                │  │ TTL 倒计时     │  │ →双花 409 演示    │  │
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
│  │  userService     createUser (M5: balance=100 if customer)│    │
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
│  │  SQLite (WAL) + better-sqlite3                            │    │
│  │  ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌────────┐  │    │
│  │  │ users    │ │ bank_keys    │ │ withdraw_│ │ spent_ │  │    │
│  │  │          │ │ (singleton)  │ │ sessions │ │ coins  │  │    │
│  │  └──────────┘ └──────────────┘ └──────────┘ └────────┘  │    │
│  │  runImmediateTx (BEGIN IMMEDIATE 写锁)                    │    │
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
    │                                  │  BEGIN IMMEDIATE:                │
    │                                  │   拒绝若已有 active session     │
    │                                  │   拒绝若 balance < amount        │
    │                                  │   UPDATE users SET balance -= 30│
    │                                  │   生成 N 个新鲜 k_i              │
    │                                  │   R_i = k_i · G                  │
    │                                  │   INSERT session(pending, +5min)│
    │                                  │  COMMIT                          │
    │  { session_id, R: [N×hex66],     │                                  │
    │    amount, N }                    │                                  │
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
    │                                  │  BEGIN IMMEDIATE:                │
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
    │                                  │  BEGIN IMMEDIATE:                │
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
    │                                  │  BEGIN IMMEDIATE:                │
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
    │                                  │  BEGIN IMMEDIATE:                │
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
│  customer_id  FK→users │        │  public_key   BLOB(33)  │
│  amount        int     │        │  private_key  BLOB(32)  │
│  n_candidates  int     │        │  created_at   datetime │
│  candidates    JSON     │        │  CHECK(id=1)            │
│  (no α_i/β_i!)         │        │  (singleton)            │
│  j_index       int?    │        └─────────────────────────┘
│  status        CHECK   │
│  created_at   datetime│        ┌─────────────────────────┐
│  expires_at   datetime│        │  spent_coins            │
└─────────────────────────┘        ├─────────────────────────┤
   UNIQUE INDEX:                  │  serial       PK BLOB(32)│
   idx_ws_active_per_customer     │  amount       int       │
   ON customer_id                 │  deposited_to FK→users  │
   WHERE status IN                │  token_hash   BLOB(32)  │
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
| POST | `/api/withdraw/init` | `{ amount }` | 201 `{ session_id, R: [hex66×N], amount, N }` | 400 `INVALID_AMOUNT` / `INSUFFICIENT_BALANCE`；409 `ACTIVE_SESSION_EXISTS` |
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

### 6.4 BEGIN IMMEDIATE 写锁串行化

`runImmediateTx` 在 SQLite WAL 模式下用 `BEGIN IMMEDIATE` 立即获取写锁，事务内：
- SELECT serial → 已存在抛 409
- INSERT spent_coins
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

## 8. 前端路由与角色门

| 路径 | 组件 | 角色门 |
|---|---|---|
| `/register` | RegisterPage | 公开 |
| `/login` | LoginPage | 公开 |
| `/dashboard` | DashboardPage | 已登录 |
| `/withdraw` | WithdrawPage | role='customer' |
| `/payment` | PaymentPage | role='merchant' |

未登录访问受保护路由 → 重定向 `/login`；角色不符 → antd Result 403。
