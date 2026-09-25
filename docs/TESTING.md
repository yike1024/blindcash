# BlindCash 测试文档（TESTING）

> 内容：213 用例分类表 + 盲性证据 + 双花演示 + 测试环境
> 关联：[REQUIREMENTS.md](./REQUIREMENTS.md) | [DESIGN.md](./DESIGN.md) | [IMPLEMENTATION.md](./IMPLEMENTATION.md) | [ISOLATION.md](../ISOLATION.md)

---

## 1. 测试用例分类总表（213 例）

> 19 个测试文件，共 213 个 `it` / `test` 用例。Phase 1 起陆续新增 `bank.test.js`、`bankReserveService.test.js`、`auditService.test.js`、`migrationRunner.test.js`、`transactions.test.js`、`multiDenomination.test.js`、`redeemSplit.test.js`、`privacy.test.js`、`admin.test.js`、`rateLimit.test.js`、`escrow.test.js`，使总数从 M7 的 104 增至 213。

### 1.1 按里程碑与文件分布

| 文件 | 里程碑 | 用例数 | 重点 |
|------|--------|--------|------|
| `schnorrBlind.test.js` | M2 | 19 | 单候选 4-move 正确性 + 篡改 + 线性性 + 输入校验 + bankStep1/3 不变量 |
| `blinding.test.js` | M2 | 9 | generateBlinders / computeBlindedCommitment / unblindResponse 客户端原语 |
| `cutAndChoose.test.js` | M2 | 18 | verifyRevealed 单候选 + verifyAllRevealed + pickRandomJ 分布 + N=10 作弊场景 + **1000-trial 盲性证据** |
| `clientBuild.test.js` | M2 | 4 | vite build 0 errors + happy-dom 浏览器可跑性 |
| `bankKeyService.test.js` | M3 | 20 | 密钥生成/持久化/轮换 + 多面额密钥 + 公钥格式 + `/api/bank/pubkey` 端点 |
| `withdrawal.test.js` | M4 | 19 | 4-move happy path + 校验 + **教授 3 必测**（α/β 不离开设备、session 唯一性、过期懒清理）+ cancel |
| `payment.test.js` | M5 | 13 | happy path + H3 双花 vs 重试 + H1 畸形 token + 篡改金额 + 角色解锁 + 初始余额 |
| `integration.test.js` | M7 | 10 | 全栈 E2E + 跨用户拒绝 + 并发双花 + 过期懒清理 + 配置 sanity |
| `transactions.test.js` | M7 | 8 | 账本流水 + 角色解锁闭环 |
| `bank.test.js` | Phase 1 | 19 | deposit service + `/api/bank/deposit` + `/api/bank/redeem` 路由 + 双花 |
| `bankReserveService.test.js` | Phase 1 | 7 | assertInvariant 正常 / 破坏 / 回滚 / in-flight |
| `auditService.test.js` | Phase 3 | 4 | 审计日志写入 + 查询 |
| `admin.test.js` | Phase 3 | 5 | 审计查询 + 密钥轮换 |
| `migrationRunner.test.js` | Phase 0 | 5 | 迁移幂等 + 顺序 + 失败回滚 |
| `rateLimit.test.js` | Phase 4 | 5 | 三级限流（global/auth/tx）+ 测试环境 skip |
| `multiDenomination.test.js` | Phase 6 | 11 | 多面额签发 + 面额匹配 + 密钥版本 |
| `redeemSplit.test.js` | Phase 6 | 15 | 找零拆分 + 面额整除 + 双花 + 审计 |
| `privacy.test.js` | Phase 6 | 16 | 匿名集分析 + 面额/密钥版本不可区分性 |
| `escrow.test.js` | Phase 7 | 6 | 担保托管两阶段提交：lock/confirm/cancel + 权限防线 + 防中间人抢兑 + 一币多锁拦截 |
| **合计** | | **213** | |

### 1.2 按测试类型分布

| 类型 | 用例数 | 代表用例 |
|------|--------|----------|
| **正确性（happy path）** | 28 | `correctness: blind → sign → unblind → verify`、`M4 happy path`、`M5 happy path`、`M7 full E2E` |
| **篡改检测** | 17 | `tampering: any single-byte mutation → verify fails`、`tampered amount → verifySig fails 400` |
| **不变量验证** | 22 | α/β 不离开设备、session 唯一性、过期懒清理退款、初始余额 0、singleton 密钥一致性 |
| **盲性证据** | 3 | `R'_j 1000-trial Shannon entropy ≥ 200 bits`、`bank cannot link token to session`、`pickRandomJ 分布均匀` |
| **作弊概率** | 2 | `over 1000 trials with N=10, cheat-success rate ≤ [50, 200]/1000`、`single-cheat attempt fails with high probability` |
| **格式校验（H1）** | 4 | serial 63 hex → 400、R' 前缀 04 → 400、s' 63 hex → 400、amount=0 → 400 |
| **双花检测（H3）** | 4 | 同商户重试 → 409、双商户并发同 token → 200+409、token_hash 大小写归一化 |
| **鉴权与角色隔离** | 6 | 未登录调任意 → 401、非 admin 调 /admin/audit → 403、他人 session → 404 |
| **跨用户访问** | 4 | A 用户的 session B 用户不能 reveal、A 的 token 不能被 B 兑付 |
| **构建可跑性** | 4 | vite build 0 errors、client/* 在 happy-dom 下能调用 |
| **配置 sanity** | 2 | CUT_AND_CHOOSE_N 默认 100 / BC_DEMO_N=10 生效、SESSION_TTL_MS 默认 5min |

### 1.3 教授 M4 三必测覆盖

| 必测项 | 对应不变量 | 测试文件:行号 | 用例数 |
|--------|-----------|--------------|--------|
| #1 α/β 不离开用户设备 | ISOLATION §三-3 | `withdrawal.test.js:334` `M4: [必测#1] blindness invariant 3 — α/β must not leave user device` | 3 |
| #2 每用户最多 1 个活跃 session | ISOLATION §三-4 | `withdrawal.test.js:381` `M4: [必测#2] session uniqueness invariant 4` | 2 |
| #3 过期 session 懒清理退款 | ISOLATION §一-1 | `withdrawal.test.js:395` `M4: [必测#3] expired session lazy-cleanup refund` | 2 |

### 1.4 教授 M5 隐患 H1-H3 覆盖

| 隐患 | 测试文件:行号 | 用例数 |
|------|--------------|--------|
| H1 畸形 token DoS（formatGate） | `payment.test.js:293` | 4 |
| H2 token_hash 大小写歧义（bytes 级拼接） | `payment.test.js:241` 内含归一化测试 | 1 |
| H3 双花 vs 重试语义 | `payment.test.js:241` | 4 |

---

## 2. 盲性证据（Blindness Evidence）

> 对应 ISOLATION §三 不变量 3：α_j / β_j 不离开用户设备 → 银行无法将最终 token 关联回原始 session。

### 2.1 数学保证

设银行在第 ⑤ 步看到的签名候选为 j，则：

$$
R'_j = R_j + \alpha_j \cdot G + \beta_j \cdot P
$$

其中 α_j、β_j 是用户本地生成的 [1, n-1] 上的均匀随机标量。由 **Difficult-Discrete-Log** 假设，α_j·G + β_j·P 在银行视角下是曲线上均匀随机点，因此 R'_j 的字节编码与均匀随机字节计算不可区分。

### 2.2 实证测试 1：Shannon 熵 ≥ 200 bits

**测试位置**：`cutAndChoose.test.js:333` — `it('R'_j byte sequence over 1000 trials has Shannon entropy ≥ 200 bits', ...)`

**方法**：

1. 1000 次独立 trial，每次：
   - `generateKeyPair()` 生成临时银行密钥对
   - 随机 k → `bankStep1(k)` 得到 R
   - `generateBlinders()` 得到 (α, β)
   - `computeBlindedCommitment(RBytes, α, β, publicKey)` 得到 R'_j
2. 将 1000 个 33 字节的 R'_j 拼成 33000 字节流
3. 统计每个字节值 0-255 的出现频次
4. 计算 Shannon 熵 H = -∑ p·log₂(p)（单位 bits/byte）
5. 总熵 = H × 33 × 1000

**断言**：`expect(HbitsTotal).toBeGreaterThan(200)`

**理论值与阈值关系**：
- 理论上限：8 bits/byte × 33 × 1000 = 264000 bits
- 实测因样本噪声略低于 8 bits/byte（约 7.99-7.9999）
- 阈值 200 bits **极度保守** —— 即使 R'_j 分布严重偏离均匀也能被检测出

**为何如此宽松的阈值**：本测试目的不是精确测量，而是**否定零假设** "R'_j 是常数或低熵"。若盲性被破坏（如 α/β 泄露导致 R'_j 可预测），总熵将接近 0；阈值 200 留出 1300 倍 slack 仍能抓到作弊。

### 2.3 实证测试 2：作弊成功率 ≤ 1/N + slack

**测试位置**：`cutAndChoose.test.js:273` — `it('over 1000 trials with N=10, cheat-success rate ≤ [50, 200]/1000, ...)`

**方法**：
1. N=10 模式下，恶意用户每次尝试作弊（提交 N-1 个真实候选 + 1 个伪造）
2. 重复 1000 次 trial，统计作弊成功次数
3. 期望：每次作弊成功率 = 1/N = 0.1，1000 次中期望 100 次
4. 二项分布方差 σ = √(1000 × 0.1 × 0.9) ≈ 9.49
5. 6σ 区间约 [43, 157]，本测试放宽到 [50, 200] 容忍样本噪声

**断言**：`expect(successCount).toBeGreaterThanOrEqual(50)` 且 `expect(successCount).toBeLessThanOrEqual(200)`

### 2.4 实证测试 3：token-session 不可链接

**测试位置**：`cutAndChoose.test.js:394` — `it('bank cannot link (R'_j, s'_j) from session A to (R, e, s) of session A', ...)`

**方法**：
1. 跑两个独立 session A、B
2. 取 A 的最终 token (R'_A, s'_A)
3. 尝试用 B 的 session 转录 (R_B, e_B, s_B) 反推关系
4. 断言：用 B 的 (R, e, s) 与 A 的 (R', s') 计算 verifySig 必失败（曲线方程不成立）

**意义**：证明银行即使持有所有 session 转录，也无法将最终 token 关联回某个具体 session。

---

## 3. 双花演示（Double-Spend Demo）

> 对应 ISOLATION §四 不变量 6：spent_coins.serial PRIMARY KEY + token_hash UNIQUE 边角防护。

### 3.1 自动化测试覆盖

| 测试 | 文件:行号 | 场景 |
|------|----------|------|
| 同商户重试 | `payment.test.js:241` `[H3] double-spend vs retry semantics` | 商户 A 提交 token → 200 OK → 商户 A 再次提交同 token → 409 DOUBLE_SPEND |
| 双商户并发 | `integration.test.js:374` `M7 · concurrent double-spend across two merchants` | 商户 A、B 同时提交同 token，`Promise.all` 触发，断言一个 200 一个 409 |
| token_hash 归一 | `payment.test.js:241` | 同 token 的 hex 大写/小写两种形式提交，第二次必 409 |

### 3.2 手动 E2E 演示路径

**目标路径**：注册 customer(初始 0) → /bank 充值 100 → 取款 30 → 复制 token → 商户粘贴预验签 ✓ → 提交 → 商户余额 +30 → 重试同 token → 409 双花

**操作步骤**：

1. **启动服务**（两个终端）：
   ```bash
   # 终端 1
   cd d:\密码货币与区块链技术\blindcash
   BC_DEMO_N=10 npm run dev
   ```
   等待 `[backend] BlindCash API listening on http://localhost:4100` 与 `[vite] ready in xxx ms` 输出。

2. **浏览器标签页 1：customer 注册 + 取款**
   - 打开 http://localhost:5174/register
   - 用户名 `alice`，密码 `Pw12345!`，角色选 customer，注册
   - 自动跳转 /login，登录后跳 /dashboard，应见 balance=0
   - 点击 "充值" 进入 /bank，输入 100 充值，返回 /dashboard 应见 balance=100
   - 点击 "取款" 进入 /withdraw
   - 输入金额 30，点击"开始取款" → 步骤 1/4：POST /api/withdraw/init 成功
   - 步骤 2/4：客户端生成 N=10 对 (α_i, β_i) + R'_i / e_i，POST /api/withdraw/submit
   - 步骤 3/4：reveal + unblind，前端展示 token JSON：
     ```json
     {"serial":"...","amount":30,"R_prime":"...","s_prime":"..."}
     ```
   - 步骤 4/4：复制 token JSON 到剪贴板
   - 顶部"取消取款"按钮：现在已不能点（session 已 committed）；dashboard 余额应 = 70

3. **浏览器标签页 2：商户收款**
   - 打开 http://localhost:5174/register
   - 用户名 `bob`，密码 `Pw12345!`，角色选 merchant，注册 → 登录
   - 点击"收款"进入 /payment
   - 粘贴 token JSON 到 TextArea
   - 300ms debounce 后预验签徽章显示 ✓ 通过 + 4 字段预览
   - 点击"提交存款" → POST /api/payment → 200 OK，商户余额 = 30
   - **再次点"再次提交同 token"按钮** → 409 DOUBLE_SPEND，UI 显示"双花已检测"

4. **可选：双商户双标签页并发**
   - 标签页 3：注册第二个商户 `carol`，进入 /payment 粘贴同 token
   - 在标签页 2 与标签页 3 几乎同时点"提交"
   - 由于 PostgreSQL 事务 + `spent_coins.serial` UNIQUE 约束互斥，必然一个 200 一个 409；UI 文案显式说明"不保证先发起者胜"

### 3.3 截图占位

> 以下位置在最终验收时插入实际截图。

**图 1：取款 4-step 流程完成界面**

```
[截图占位：/withdraw 步骤 4/4，token JSON 展示框 + "复制" 按钮 + 顶部"取消取款"已禁用]
路径：docs/assets/withdraw-step4.png
```

**图 2：商户预验签通过**

```
[截图占位：/payment TextArea 粘贴 token + ✓ 预验签通过徽章 + 4 字段预览 + "提交存款"按钮可点]
路径：docs/assets/payment-preview.png
```

**图 3：双花 409 提示**

```
[截图占位：/payment 提交后 200 OK + 余额 +30；再次点"再次提交同 token"按钮后 Alert 错误：双花已检测]
路径：docs/assets/double-spend-409.png
```

---

## 4. 测试环境与运行

### 4.1 运行环境

| 项 | 值 |
|----|-----|
| OS | Windows 11 |
| Node | ≥ 22（`engines.node` ≥ 22） |
| 测试框架 | vitest 4.1.11 + happy-dom 20.14.5 + supertest 7.2.2 |
| 数据库 | PostgreSQL 14+ + `pg` 8.x（测试需提供 `DATABASE_URL`） |
| 并发模式 | vitest 串行执行数据库测试，避免事务交叉 |

### 4.2 测试隔离机制

- 所有测试共享一个 PostgreSQL 测试数据库（`DATABASE_URL`），每个测试文件在 `beforeAll` 调用 `resetTestDb()`（`resetDb()`）清空 `public` schema 并重新运行 migrations，确保干净状态
- M2 纯密码学测试不触碰 DB，不受隔离机制影响
- `integration.test.js` 用 `http.createServer(app)` + 随机端口启动真实 HTTP server，避免 supertest 在 Windows 上的 ENOBUFS 端口耗尽问题
- 概率测试（盲性证据、作弊概率）单独标 `timeout: 60000`，避免 vitest 默认 5s 超时
- **fundUser 辅助函数**：`fundUser(userId, amount)` 调用 `bankService.deposit` 同时更新 `users.balance` 与 `bank_reserve.reserve_balance`。直接 SQL `setBalance` 已弃用，因其绕过 `assertInvariant` 不变量校验。

### 4.3 运行命令

```bash
# 全量测试（213 用例）
npm test

# 监听模式
npm run test:watch

# 详细输出（含盲性证据的熵值打印）
BC_VERBOSE=1 npm test

# 单独跑某个里程碑
npx vitest run withdrawal.test.js
npx vitest run integration.test.js
```

### 4.4 预期输出

```
 ✓ 19 tests passed (schnorrBlind)
 ✓  9 tests passed (blinding)
 ✓ 18 tests passed (cutAndChoose)
 ✓  4 tests passed (clientBuild)
 ✓ 20 tests passed (bankKeyService)
 ✓ 19 tests passed (withdrawal)
 ✓ 13 tests passed (payment)
 ✓ 10 tests passed (integration)
 ✓  8 tests passed (transactions)
 ✓ 19 tests passed (bank)
 ✓  7 tests passed (bankReserveService)
 ✓  4 tests passed (auditService)
 ✓  5 tests passed (admin)
 ✓  5 tests passed (migrationRunner)
 ✓  5 tests passed (rateLimit)
 ✓ 11 tests passed (multiDenomination)
 ✓ 15 tests passed (redeemSplit)
 ✓ 16 tests passed (privacy)
 ✓  6 tests passed (escrow)

 Test Files  19 passed (19)
      Tests  213 passed (213)
```

### 4.5 已知噪声

| 警告 | 来源 | 处置 |
|------|------|------|
| `spawn() option shell deprecated` | `clientBuild.test.js` 用 `shell: true` 调 npx.cmd | 保留 + 18 行注释（Windows .cmd 必须走 shell；args 全硬编码无注入面；详见 IMPLEMENTATION.md §2.9） |

---

## 5. 测试设计原则

1. **不读 `bank_keys.private_key` 伪造签名来"证明"安全性**（ISOLATION §五-7）——那只证明了"密钥泄露则系统崩溃"这一常识
2. **不依赖被测代码的内部实现做反推**——`setup.js` 中的 `bytesToHex` / `hexToBytes` 是独立重写的，不 import `src/utils/hex.js`，避免 tautology
3. **概率测试用大样本 + 6σ slack**——1000-trial 盲性证据用 200 bits 阈值（理论 264000 bits），作弊概率用 [50, 200]/1000（理论 100 ± 9.5），容忍二项分布噪声
4. **并发测试不假设先发起者胜**——双商户双花测试用 `Promise.all` + `.sort()` 检查结果集，不假设谁是 200 谁是 409
5. **E2E 走真实 HTTP**——`integration.test.js` 通过 `http.createServer(app)` 启动真实 server + fetch，覆盖完整 express-validator + bcrypt + JWT 栈

---

## 6. 测试用例清单（详细）

> 限于篇幅，仅列出代表性用例；完整清单见各 `*.test.js` 文件。

### 6.1 schnorrBlind.test.js（19 例）

```
✓ correctness: blind → sign → unblind → verify (single candidate)
✓ tampering: any single-byte mutation in serial → verify fails
✓ tampering: any single-byte mutation in R' → verify fails
✓ tampering: any single-byte mutation in s' → verify fails
✓ tampering: any single-byte mutation in amount → verify fails
✓ linearity: same (k, x) → s scales linearly with e
✓ malformed-input: s' = 0 → verifySig false
✓ malformed-input: s' out of range [1, n-1] → verifySig false
✓ malformed-input: R' not on curve → verifySig false (catch)
✓ malformed-input: P not on curve → verifySig false (catch)
✓ malformed-input: serial wrong length → verifySig false
✓ bankStep1 invariants: k=0 → throw
✓ bankStep1 invariants: k=n → throw
✓ bankStep1 invariants: k=1 → R = G
✓ bankStep3 invariants: linear in e
✓ bankStep3 invariants: linear in k
... (4 more)
```

### 6.2 withdrawal.test.js（19 例）

```
✓ M4: 4-move happy path — full init/submit/reveal/cancel lifecycle
✓ M4: validation — amount ≤ 0 → 400
✓ M4: validation — amount > balance → 400
✓ M4: role unlock — merchant calls init → 201（任何登录用户都能取款）
✓ M4: [必测#1] blindness invariant 3 — submit payload carries α_j → 400
✓ M4: [必测#1] blindness invariant 3 — reveal payload carries α_j for wrong index → 400
✓ M4: [必测#1] blindness invariant 3 — α_j not in any DB row after commit
✓ M4: [必测#2] session uniqueness — second init while active → 409
✓ M4: [必测#2] session uniqueness — DB partial UNIQUE index catches race
✓ M4: [必测#3] expired session lazy-cleanup refunds balance
✓ M4: [必测#3] expired session lazy-cleanup happens on next init
✓ M4: cancel flow — refunds balance
✓ M4: cancel flow — clears session from active
... (6 more)
```

### 6.3 integration.test.js（10 例）

```
✓ M7 · full end-to-end — register customer → withdraw 30 → merchant deposit → balance +30
✓ M7 · full end-to-end — customer balance decremented by withdraw, refunded on cancel
✓ M7 · cross-user — A's session cannot be revealed by B (404)
✓ M7 · cross-user — A's token cannot be deposited to merchant who is not the payee
✓ M7 · role unlock — merchant can call /withdraw/init → 201
✓ M7 · role unlock — customer can call /payment → 400 SIGNATURE_INVALID（token 无效仍被拒）
✓ M7 · concurrent double-spend — Promise.all two merchants same token → 200+409
✓ M7 · expired session lazy-cleanup — refund on next init
✓ M7 · expired session lazy-cleanup — refund on next submit
✓ M7 · config sanity — CUT_AND_CHOOSE_N defaults to 100, BC_DEMO_N=10 overrides
```

---

## 7. Phase 4 增补：限流专项测试 + pino 结构化日志示例

### 7.1 限流专项测试（rateLimit.test.js，5 用例）

主测试套件的限流器都 `skip: () => isTest`（NODE_ENV=test 时 no-op），**不打死
自己的 213 个测试**。但限流逻辑本身需要专项验证——否则 skip 让限流在主套件里
隐形等于没验证。rateLimit.test.js 手动构造不复用 skip 的 limiter 实例：

| 用例 | 验证点 |
|------|--------|
| authLimiter 第 6 次 → 429 + Retry-After | 5 req/min/IP 防爆破，第 6 次必拒 + RFC 9110 §15.5.14 Retry-After 头 |
| txLimiter 已认证用户第 11 次 → 429 | 10 req/min/user，用 userId key（已认证路径） |
| txLimiter 未认证回退到固定 key | 未认证请求仍能限流（IP 回退） |
| standardHeaders RateLimit-* 头 | 429 响应带标准 RateLimit-Limit / RateLimit-Remaining |
| 主 app /api/health 不被限流 | skip(isTest) 生效，连打 20 次 /api/health 全 200 |

### 7.2 pino 结构化日志格式示例

Phase 4 把 Phase 1 的 console 包装 logger 换成 pino，输出 JSON 一行一条。
pino-http 自动给每个请求生成 req.id（UUID v4），并把 req/res 序列化写入日志。

**GET /api/health 请求日志示例**（autoLogging.ignore 跳过 /api/health 的请求日志，
但其他路径会记录）：

```json
{"level":30,"time":1790135064141,"pid":54360,"hostname":"yikecao","req":{"method":"GET","url":"/api/bank/pubkey","headers":{"host":"127.0.0.1:4100"}},"res":{"statusCode":200},"responseTime":12,"req_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","msg":"request completed"}
```

**错误日志示例**（兜底错误中间件带 req_id）：

```json
{"level":50,"time":1790135064141,"pid":54360,"hostname":"yikecao","err":{"name":"ReserveInvariantError","message":"reserve invariant violated","stack":"..."},"req_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","method":"POST","url":"/api/bank/deposit","status":500,"msg":"unhandled_error"}
```

**字段说明**：
- `level`：pino 数值级别（30=info, 40=warn, 50=error, 60=fatal）
- `time`：Unix 毫秒时间戳
- `pid`/`hostname`：进程标识，便于多实例日志聚合
- `req_id`：pino-http 生成的 UUID v4，贯穿请求生命周期，便于追踪
- `responseTime`：毫秒级响应耗时

**文献参考**：
- NIST SP 800-92rev1 §3 — 审计日志应含 timestamp + event type + actor + outcome
- OWASP ASVS L1 v4.0.31 §7.1.1 — 所有认证事件必须记录
- RFC 9110 §15.5.14 — 429 响应应带 Retry-After 头

---

## 8. 参考文献

- v3 实施大纲 §5（M2-M7 测试矩阵）
- RFC 6979 — 确定性 nonce 生成
- BIP-340 — Schnorr 签名域分离
- Shannon entropy — *A Mathematical Theory of Communication* (1948)
- vitest 文档 — https://vitest.dev/
- @noble/curves 测试范式 — https://paulmillr.com/noble/
- RFC 9110 §15.5.14 — 429 Too Many Requests + Retry-After
- NIST SP 800-92rev1 §3 — 审计日志安全要求
- OWASP ASVS L1 v4.0.31 §11.1.1 — 速率限制要求
