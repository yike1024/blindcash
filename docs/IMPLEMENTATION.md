# BlindCash 实现文档（IMPLEMENTATION）

> 内容：M1-M7 里程碑落地清单 + 关键工程决策 + 风险评估与处置
> 关联：[REQUIREMENTS.md](./REQUIREMENTS.md) | [DESIGN.md](./DESIGN.md) | [TESTING.md](./TESTING.md) | [ISOLATION.md](../ISOLATION.md)

---

## 1. 里程碑落地清单（M1-M7）

| 里程碑 | 范围 | 关键产物 | commit | 测试 |
|--------|------|----------|--------|------|
| **M1** | 身份层 | `users` 表、`/api/auth/register`、`/api/auth/login`（bcrypt + JWT + role）、`/api/health`、PostgreSQL + `pg` 连接池 | — | 13 |
| **M2** | 密码学层 | `crypto/server/curve.js`（secp256k1）、`hashToScalar.js`（域分离 tag）、`schnorrBlind.js`（4-move bankStep1/3 + verifySig）、`crypto/client/blinding.js`（generateBlinders / computeBlindedCommitment / unblindResponse）、`cutAndChoose.js`（verifyRevealed + pickRandomJ） | — | 50 |
| **M3** | 银行密钥层 | `bank_keys` 表（singleton）、`bankKeyService.js`（getOrGenerate + assertKeypairConsistent）、`/api/bank/pubkey`（无认证公开）、`initDb.js`、`app.js` 启动时初始化 | c0ae174 | 12（累计 62） |
| **M4** | 取款层 | `withdrawal_sessions` 表（状态机 + 部分 UNIQUE 索引）、`withdrawalService.js`（init/submit/reveal/cancel + lazyCleanup）、`/api/withdraw/*` 4 路由（customerGuard）、`WithdrawalError` | 9b76aba | 19（累计 81） |
| **M5** | 支付层 | `spent_coins` 表、`paymentService.js`（formatGate H1 + computeTokenHash H2 + processPayment H3）、`/api/payment`（merchantGuard）、初始余额（M5 时为 100，Phase 1 改为 0 + 自助充值，见 userService.js） | a01ba90 | 13（累计 94） |
| **M6** | 前端 E2E | `Withdraw.jsx`（4-step Steps + α/β useRef + TTL 倒计时 + beforeunload 守卫 + mapApiError）、`Payment.jsx`（粘贴 token + 300ms debounce 预验签 + 双花 409 演示）、`AuthContext.jsx`（updateUser）、`AppLayout.jsx`（role 菜单）、`vite.config.js`（@crypto/@config/@utils 别名 + fs.allow） | 20c6699 / 96c258f | clientBuild 4/4 + oxlint 0/0 + vite build 0 errors |
| **M7** | 集成测试 + 文档 + 角色解锁 | `integration.test.js`（10 用例：E2E + 跨用户 + 并发双花 + 过期懒清理 + 配置 sanity）、`transactions.js` 账本、`/withdraw/*` 与 `/payment` 取消角色锁、ISOLATION.md 补证据 | b6fc0c7 | 10（累计 104） |
| **Phase 0-1** | 迁移系统 + 充值/退币 + 准备金 | `migrationRunner.js`、`bankReserveService.js`（assertInvariant）、`bankService.deposit/redeem`、初始余额改为 0 | — | 31（累计 135） |
| **Phase 2** | 客户端 IndexedDB 钱包 | `walletDB.js`（前端，后端无 wallet 表）、`Wallet.jsx` | — | 前端 8 |
| **Phase 3** | 审计 + 密钥轮换 + admin | `audit_log` 表、`auditService.js`、`bankKeyService.rotateKey`、`admin.js`（`requireRole('admin')`） | — | 9（累计 144） |
| **Phase 4** | 限流 + 结构化日志 | `rateLimit.js`（三级限流）、`pino-http` + `logger.js` | — | 5（累计 149） |
| **Phase 5** | Docker + Swagger | `Dockerfile`、`docker-compose.yml`、`/api/docs`、express.static 托管前端 | — | — |
| **Phase 6** | 多面额 + 找零 + 隐私 | `DENOMINATIONS`、`/api/bank/pubkeys`、`redeem-split`、`privacy.js` 匿名集分析 | — | 42（累计 191） |
| **Phase 7** | 担保托管收款 | `payment_escrows` 表、`escrowService.js`（create/lock/confirm/cancel）、`escrow.test.js` | — | 22（累计 213） |

> 详见各 commit 的 git show。所有里程碑落地前均满足：后端测试全绿、`vite build` 0 errors、`oxlint` 0 warnings。
>
> **测试归属说明**：M1 身份层没有独立测试文件，注册/登录的协议级覆盖现由 `integration.test.js`（10 用例）与 `payment.test.js`（2 个注册用例）承担；M2 的 50 个用例对应 `schnorrBlind`(19) + `blinding`(9) + `cutAndChoose`(18) + `clientBuild`(4)。后端累计 213 = M7 的 104 + Phase 1-7 的 109。前端另有 `walletDB.test.js` 8 例。

---

## 2. 关键工程决策

### 2.1 从 3-move 改为 4-move cut-and-choose（v2 → v3）

**背景**：v2 实施大纲的 3-move Schnorr 盲签名（bank→user R、user→bank e、bank→user s）在"银行不可链接 token 到用户"上存在缺陷——银行记住了 (R, e) 后，token 中的 (R', s') 经过反盲化后 R' = R + α·G + β·P，但银行仍可尝试碰撞 (R, e) 与 (R', s')。

**修正**：采用 v3 §2.3 的 **cut-and-choose 4-move** 协议：

1. ① init：银行生成 N 个 (k_i, R_i=k_i·G)，存入 session（pending）
2. ② submit：用户生成 N 对 (α_i, β_i)，对每个 i 计算 R'_i = R_i + α_i·G + β_i·P 与 e'_i = H(tag‖R'_i‖serial_i‖amount‖P)，再计算盲化挑战 e_i = (e'_i + β_i) mod n，提交 N 个 (R'_i, e_i) 给银行
3. ③ bank pick j：银行从 N 个中随机挑 j，要求用户对 i ≠ j 揭示 (α_i, β_i) 以验证 R'_i / e_i 的构造正确性
4. ⑤ reveal：用户验证全部 i ≠ j 通过后，揭示 j 的位置；银行计算 s_j = (k_j + e_j·x) mod n 返回
5. ⑥ unblind：用户计算 s'_j = (s_j + α_j) mod n，得到 token = (serial_j, amount, R'_j, s'_j)

**关键性质**：银行在第 ⑤ 步只看到 j 的 e_j（已被 β_j 盲化），且 j 是在用户提交 N 个候选之后才随机选定的——cut-and-choose 使得银行以 (1 - 1/N) 概率抓到作弊者；N=100 时作弊成功率 ≤ 1%。同时，银行无法将最终 token (R'_j, s'_j) 关联回原始 session：因为 j 索引在签名后才确定，且 α_j/β_j 从不离开用户本地。

**落地位置**：`backend/src/crypto/server/schnorrBlind.js`（bankStep1 / bankStep3 / verifySig）、`backend/src/crypto/server/cutAndChoose.js`（verifyRevealed / pickRandomJ）、`backend/src/crypto/client/blinding.js`（generateBlinders / computeBlindedCommitment / unblindResponse）、`backend/src/services/withdrawalService.js`（4 路由状态机）。

### 2.2 @noble/secp256k1 + @noble/hashes 选型（弃用 elliptic）

**决策**：使用 `@noble/secp256k1@^2.1.0` + `@noble/hashes@^1.5.0`，**不使用** 早期 M2 草稿中考虑的 `elliptic`。

**理由**：

| 维度 | @noble/secp256k1 | elliptic |
|------|------------------|----------|
| 浏览器可跑 | ✅ 纯 JS、无 Node 内建依赖、无 WASM | ⚠ 依赖 `bn.js`，需 vite-plugin-node-polyfills 兜底 Buffer/process |
| 常数时间 | ✅ 官方声明 constant-time 算术 | ❌ 非常数时间，时序侧信道风险 |
| API 设计 | ✅ Point 类不可变、`.multiply()` / `.add()` 链式 | ⚠ Point 可变，需手动 clone |
| 维护活跃度 | ✅ Paul Miller 持续维护、被 bitcoinjs/wallet 等广泛使用 | ⚠ 近年几乎停滞 |
| 包体积 | ✅ ~50KB | ⚠ ~150KB |

**落地**：`crypto/server/curve.js` 重新导出 G/n/modN/scalarToBytes/bytesToScalar/encodePoint/decodePoint/randomScalar，`crypto/server/hashToScalar.js` 用 `@noble/hashes/sha256`。前端 `vite.config.js` 仍保留 `vite-plugin-node-polyfills` 兜底 Buffer/process 全局，让任何残留的 Node 全局引用都能在浏览器跑起来（v3 §一-1 前端密码学边界）。

### 2.3 α/β 只在前端 useRef 内存（教授风险 #3）

**决策**：盲化因子 α_j、β_j **绝不写入 sessionStorage**，只存在 `frontend/src/pages/Withdraw.jsx` 中的 `useRef([])`。

**实现要点**：

- `const blindersRef = useRef([])` —— 用 useRef 而非 useState：useRef 不会触发重渲染，且 React 不会在 dev 工具中序列化它；useState 会触发重渲染且在 React DevTools 中可见
- 提交 step1 时一次性写入 `blindersRef.current = [α_1, β_1, ..., α_N, β_N]`
- 第 ⑤ 步 unblind 成功后立即 `blindersRef.current = []` 清空（ISOLATION §三-3）
- `sessionActiveRef` + `beforeunload` 事件：用户刷新 / 关闭标签页时弹窗警告"将丢失盲化因子，本次取款需重新发起"
- "取消取款"按钮：调用 `POST /api/withdraw/cancel` 触发后端退款后清空 blindersRef

**教授风险 #3 的显式 caveat（写入 docs）**：

> useRef 仅保证 α/β 不被 React 序列化到 sessionStorage；它**不是**进程隔离机制。真正的"α/β 永不离开用户设备"假设依赖浏览器同源策略 + 进程隔离。在教学演示语境下，这意味着：
> - 同一浏览器内不同的标签页是**独立 JS realm**，α/β 不会跨标签页泄露（支撑双商户双标签页双花演示）
> - 但若用户打开 DevTools 手动读取 `blindersRef.current`，则可拿到 α/β —— 这是"用户自己攻击自己"，不构成对协议的攻击
> - 生产级隔离需要 Web Worker / WASM / TEE，超出本课程范围

**落地**：`frontend/src/pages/Withdraw.jsx` 第 1-50 行的 useRef 声明与 beforeunload 守卫、第 180 行 `blindersRef.current = []` 的即时清空。

### 2.4 BC_DEMO_N=10 演示降速（vs 生产 N=100）

**决策**：`backend/src/config/bank.js` 中 `CUT_AND_CHOOSE_N = Number(process.env.BC_DEMO_N) || 100`，默认 100；运行 `BC_DEMO_N=10 npm run dev` 时降为 10。

**理由**：

- N=100 时单次取款的 submit 阶段需在前端生成 100 对 (α_i, β_i) 并计算 100 个 R'_i / e_i，浏览器侧约 1-2 秒；reveal 阶段需验证 99 对 (α_i, β_i) 的构造正确性，后端侧约 200-500ms
- 教学演示中需在 5 分钟 TTL 内跑完 init→submit→reveal→unblind 全流程，N=10 时总耗时 < 300ms，演示流畅
- 风险：N=10 时 cut-and-choose 作弊成功率为 10%（远高于 N=100 的 1%）；**demo only**，生产必须 N=100
- 在 `config/bank.js` 顶部注释和 `docs/DESIGN.md` 中均显式标注此约束

**测试覆盖**：`M2.test.js` 中 `cutAndChoose.verifyRevealed` 测试用 N=10；`integration.test.js` 的 E2E 用例也用 N=10；但盲性证据测试（1000-trial entropy ≥ 200 bits）独立运行，不受 BC_DEMO_N 影响。

### 2.5 runImmediateTx 原子写事务（PostgreSQL 事务）

**决策**：所有涉及余额变动的写操作都包裹在 `backend/src/models/db.js` 的 `runImmediateTx(fn)` 中，该函数执行 `BEGIN` → `fn()` → `COMMIT`，任何 throw 则 `ROLLBACK`。底层使用 PostgreSQL 单连接事务（`pg` PoolClient），事务内所有查询在同一连接上执行，保证原子性。

**为什么用单连接事务 + UNIQUE 约束**：

- 双花检测依赖 `spent_coins.serial` 的 UNIQUE 约束：两个并发事务都尝试 INSERT 同一 serial，PostgreSQL 只允许一个成功，另一个抛 23505（unique_violation），由 service 层映射为 409 DOUBLE_SPEND
- 事务内先 `SELECT serial → 409` 再 `INSERT`，配合 UNIQUE 约束形成双层防护；事务失败整体回滚，不会出现"余额加了但 spent_coins 没插"的半状态

**落地位置**：

- `withdrawalService.initWithdrawal`：`runImmediateTx(() => { SELECT balance → UPDATE balance → INSERT session })` —— 原子扣款 + 建会话
- `withdrawalService.cancelWithdrawal` / `lazyCleanupExpiredSessions`：`runImmediateTx(() => { UPDATE balance += amount → UPDATE session.status })` —— 原子退款 + 状态推进
- `paymentService.processPayment`：`verifySig` 在事务外（只读曲线运算无锁）→ `runImmediateTx(() => { SELECT serial → 409 or INSERT spent_coins + UPDATE merchant.balance })` —— 原子双花检测 + 入账

**教授 H3 铁律**：`verifySig 必须在事务外`——否则写锁会持有 ms 级曲线运算时间，严重降低并发吞吐。

### 2.6 token_hash 字节级拼接（教授 H2 防大小写歧义）

**决策**：`paymentService.computeTokenHash` 用 `createHash('sha256').update(Buffer.concat([serialBytes, RPrimeBytes, sPrimeBytes]))`，**不是** 拼接 hex 字符串。

**风险**：若 token_hash = SHA256(serial_hex ‖ R_prime_hex ‖ s_prime_hex)，则同一 token 在 hex 大小写不同时（`0a` vs `0A`）会产生两个不同的 token_hash，绕过 `spent_coins.token_hash` UNIQUE 索引——攻击者只需把 token 中的 hex 字符大写化就能双花。

**字节级拼接的好处**：serial/R'/s' 都先 `hexToBytes` 转成 Uint8Array，再 `Buffer.concat`——任何 hex 大小写差异在字节级都被归一化，同一个逻辑 token 只会有一个 token_hash。

**测试覆盖**：`payment.test.js` 中 "token_hash 大小写归一化测试"——同一 token 的 hex 大写、小写两种形式经过 processPayment 后，第二次必须返回 409 DOUBLE_SPEND。

### 2.7 vite.config.js 跨边界别名（@crypto/@config/@utils）

**问题**：前端 `Withdraw.jsx` / `Payment.jsx` 需要复用后端的 `crypto/client/blinding.js`、`crypto/client/schnorrBlindClient.js`、`crypto/server/curve.js`、`config/bank.js`、`utils/hex.js`——但前端目录与后端目录是平级的，相对路径会写成 `../../../backend/src/crypto/client/blinding.js`，可读性差且 vite 默认不允许跨 root 导入。

**决策**：`frontend/vite.config.js` 中加 3 个 alias：

```js
'@crypto':  resolve(__dirname, '../backend/src/crypto'),
'@config':  resolve(__dirname, '../backend/src/config'),
'@utils':   resolve(__dirname, '../backend/src/utils'),
```

配合 `server.fs.allow: ['..']` 让 vite 允许提供 backend/ 下的文件。

**好处**：前端导入写成 `import { generateBlinders } from '@crypto/client/blinding.js'`，与后端导入完全一致，便于维护。`clientBuild.test.js` 在 M2 时已验证这些模块在浏览器可跑（vite build + happy-dom）。

### 2.8 端口分配 4100 / 5174（与 cryptobank 不冲突）

**决策**：blindcash 后端用 `PORT=4100`，前端 vite dev server 用 `port: 5174`，与同机的 cryptobank 项目（4000 / 5173）错开，可同时运行。

**落地**：`backend/src/app.js` 中 `const PORT = process.env.PORT || 4100`，`cors({ origin: ['http://localhost:5174', 'http://127.0.0.1:5174'] })`，`frontend/vite.config.js` 中 `port: 5174` + `proxy: { '/api': { target: 'http://localhost:4100' } }`。

### 2.9 clientBuild.test.js spawn shell:true 保留（教授风险 #5）

**背景**：`backend/tests/clientBuild.test.js` 通过 `child_process.spawn('npx', ['vite', 'build'], { cwd: FRONTEND_DIR, shell: true })` 调用 vite build 验证前端构建产物。Node 24 在 Windows 上对 `shell: true` 触发 DeprecationWarning。

**决策**：保留 `shell: true`，添加 18 行注释说明理由。

**理由**：

1. Windows 上 `npx` 实际是 `npx.cmd` 批处理脚本，Node 的 `child_process.spawn` 在 Windows 上**无法直接执行 .cmd 文件**，必须通过 shell（cmd.exe）转发
2. 尝试 `shell: false` + `spawn('npx.cmd', args)` 会抛 `spawn EINVAL`，更糟
3. spawn 的 args 全部硬编码（`['--prefix', '../frontend', 'build']`），**没有任何用户输入**进入命令行，不存在注入面
4. DeprecationWarning 是非阻塞的 CI 噪声，不影响测试结果

**替代方案评估**：可改用 `execFile` 或 `exec`，但二者要么同样依赖 shell，要么 API 行为差异更大。保留 spawn + shell:true 是最务实的方案。

---

## 3. 风险评估与处置（对应教授 M6/M7 风险表）

| # | 风险 | 等级 | 处置 | 落地证据 |
|---|------|------|------|----------|
| #1 | 初始余额并发竞态（多 customer 同时充值同时取款，余额可能扣超） | H | Phase 1 后注册 balance=0，充值（deposit）与取款均由 `runImmediateTx` 包裹 SELECT balance → UPDATE → INSERT，写锁互斥 | `userService.js` register 函数、`bankService.deposit`、`withdrawalService.initWithdrawal` |
| #2 | `/attack` 演示页缺失 | M | M7 阶段三（可选）补；当前文档中明确说明双花演示通过双标签页手动操作完成 | `docs/TESTING.md` 双花演示节 |
| #3 | α/β useRef 仅 React 内存，非进程隔离 | H | 见 §2.3 显式 caveat；教学语境下可接受 | `docs/IMPLEMENTATION.md` §2.3 |
| #4 | cut-and-choose N=10 演示降速 | M | 默认 N=100，仅 BC_DEMO_N=10 时降速；docs 显式标注 demo only | `config/bank.js`、`docs/IMPLEMENTATION.md` §2.4 |
| #5 | clientBuild.test.js spawn DeprecationWarning | L | 保留 shell:true + 18 行注释，非阻塞噪声 | `backend/tests/clientBuild.test.js` |
| #6 | token_hash 大小写歧义（hex 编码差异） | H | 字节级 Buffer.concat 而非 hex 字符串拼接 | `paymentService.computeTokenHash`、§2.6 |
| #7 | verifySig 在事务内导致吞吐降低 | H | verifySig 在事务之外执行，事务只包裹写动作 | `paymentService.processPayment`、§2.5 |

---

## 4. 依赖与运行环境

| 维度 | 选择 | 版本 | 备注 |
|------|------|------|------|
| Node | LTS | >=24 | `engines.node` 声明，使用 `globalThis.crypto` webcrypto |
| 后端框架 | Express | ^4.21.2 | |
| 数据库 | pg (PostgreSQL) | ^8.13.1 | 连接池 + 事务 + UNIQUE 约束双花防护 |
| 密码学 | @noble/secp256k1 | ^2.1.0 | 见 §2.2 选型理由 |
| Hash | @noble/hashes | ^1.5.0 | sha256 域分离 |
| 密码哈希 | bcrypt | ^5.1.1 | rounds=12 |
| JWT | jsonwebtoken | ^9.0.2 | HS256 |
| 验证 | express-validator | ^7.2.0 | register/login 字段校验 |
| 前端框架 | React + Vite | 19 + 8 | |
| UI 库 | antd | 6 | Steps / InputNumber / Alert |
| 测试 | vitest | ^4.1.11 | + happy-dom + supertest |
| Polyfill | vite-plugin-node-polyfills | — | Buffer / process 兜底 |

**启动命令**：

```bash
npm run install:all          # 安装前后端依赖
export DATABASE_URL="postgres://user:pass@host:5432/blindcash"  # PostgreSQL 连接串
npm run init:db              # 运行 migrations 创建 schema + 生成银行密钥
npm run dev                  # concurrently 启动 backend(4100) + frontend(5174)
BC_DEMO_N=10 npm run dev     # 演示模式（cut-and-choose N=10）
npm test                     # 后端 vitest 全量测试
```

---

## 5. 目录结构

```
blindcash/
├── backend/
│   ├── package.json
│   ├── vitest.config.js
│   ├── src/
│   │   ├── app.js                    # Express 入口（M1-M7 + admin/privacy 路由挂载）
│   │   ├── config/
│   │   │   └── bank.js               # DENOMINATIONS / CUT_AND_CHOOSE_N / SESSION_TTL_MS / TOKEN_DOMAIN_TAG
│   │   ├── crypto/
│   │   │   ├── server/
│   │   │   │   ├── curve.js          # secp256k1 G/n/modN/encodePoint/decodePoint
│   │   │   │   ├── hashToScalar.js  # 域分离 tag + sha256 → scalar mod n
│   │   │   │   ├── schnorrBlind.js  # bankStep1/3 + verifySig
│   │   │   │   └── cutAndChoose.js  # verifyRevealed + pickRandomJ
│   │   │   └── client/               # 浏览器可跑子集（vite build 验证）
│   │   │       ├── blinding.js       # generateBlinders / computeBlindedCommitment / unblindResponse
│   │   │       ├── schnorrBlindClient.js  # userComputeChallenge + verifySig（预验签）
│   │   │       ├── pointFormat.js    # 33B 压缩点格式校验
│   │   │       └── protocolConstants.js   # TOKEN_DOMAIN_TAG（零 Node 依赖）
│   │   ├── models/
│   │   │   ├── db.js                 # queryOne / runWrite / runImmediateTx
│   │   │   ├── initDb.js            # 命令行初始化
│   │   │   ├── schema.sql           # 9 张表（users / bank_keys / ... / payment_escrows）
│   │   │   ├── schema_migrations.sql # 迁移记录表
│   │   │   └── migrations/          # 001-010 迁移脚本
│   │   ├── routes/
│   │   │   ├── auth.js              # /api/auth/register /login /me
│   │   │   ├── bank.js              # /api/bank/pubkey /pubkeys /reserve /deposit /redeem /redeem-split
│   │   │   ├── withdrawal.js        # /api/withdraw/init /submit /reveal /cancel
│   │   │   ├── payment.js           # /api/payment + escrow/lock/confirm/cancel
│   │   │   ├── transactions.js      # /api/transactions 账本
│   │   │   ├── admin.js             # /api/admin/audit /rotate-key（requireRole('admin')）
│   │   │   └── privacy.js           # 匿名集分析
│   │   ├── services/
│   │   │   ├── authService.js       # 注册 / 登录
│   │   │   ├── userService.js       # INITIAL_BALANCE_CUSTOMER=0 / 余额读写
│   │   │   ├── bankKeyService.js    # getOrGenerate + rotateKey + assertKeypairConsistent
│   │   │   ├── bankService.js       # deposit / redeem / redeem-split
│   │   │   ├── bankReserveService.js# assertInvariant 准备金不变量
│   │   │   ├── withdrawalService.js # 4-move 状态机 + WithdrawalError
│   │   │   ├── paymentService.js    # formatGate + computeTokenHash + processPayment
│   │   │   ├── escrowService.js     # create/lock/confirm/cancel 两阶段托管
│   │   │   ├── transactionService.js# 账本读写
│   │   │   ├── auditService.js      # 审计日志
│   │   │   ├── privacyService.js    # 匿名集统计
│   │   │   └── sessionCleanupService.js # 过期会话懒清理
│   │   ├── utils/
│   │   │   ├── hex.js
│   │   │   ├── pointEncoding.js
│   │   │   ├── migrationRunner.js   # 迁移执行器
│   │   │   └── logger.js            # pino 结构化日志
│   │   └── middleware/
│   │       ├── auth.js              # requireAuth（JWT 解析）
│   │       ├── requireRole.js       # requireRole('customer'|'merchant'|'admin')
│   │       └── rateLimit.js         # 三级限流
│   └── tests/
│       ├── helpers/                 # fundUser / testDb
│       ├── setup.js                 # bytesToHex / hexToBytes / randomBytes
│       ├── schnorrBlind.test.js     # 19 用例（M2）
│       ├── blinding.test.js         # 9 用例（M2）
│       ├── cutAndChoose.test.js     # 18 用例（M2 含 1000-trial 盲性证据）
│       ├── bankKeyService.test.js   # 12 用例（M3）
│       ├── withdrawal.test.js       # 19 用例（M4）
│       ├── payment.test.js          # 13 用例（M5）
│       ├── integration.test.js      # 10 用例（M7 E2E + 跨用户 + 并发 + 过期）
│       ├── clientBuild.test.js      # 4 用例（vite build 0 errors）
│       ├── bank.test.js             # 充值 / 退币 / 找零（Phase 1/6）
│       ├── bankReserveService.test.js
│       ├── migrationRunner.test.js
│       ├── multiDenomination.test.js
│       ├── redeemSplit.test.js
│       ├── admin.test.js            # admin 审计 / 轮换（Phase 3）
│       ├── auditService.test.js
│       ├── rateLimit.test.js        # 限流（Phase 4）
│       ├── privacy.test.js          # 匿名集（Phase 6）
│       ├── escrow.test.js           # 6 用例（Phase 7 托管）
│       └── transactions.test.js
├── frontend/
│   ├── package.json
│   ├── vite.config.js               # @crypto/@config/@utils alias + fs.allow + port 5174
│   └── src/
│       ├── App.jsx                  # 路由表
│       ├── main.jsx
│       ├── api/client.js            # axios 封装 + JWT 注入
│       ├── context/AuthContext.jsx  # useAuth + updateUser
│       ├── components/
│       │   ├── AppLayout.jsx        # 导航菜单
│       │   ├── ProtectedRoute.jsx   # 未登录跳 /login
│       │   └── CollapsibleHint.jsx
│       ├── utils/
│       │   └── walletDB.js          # IndexedDB 客户端钱包
│       ├── pages/
│       │   ├── Login.jsx / Register.jsx
│       │   ├── Dashboard.jsx        # balance + role
│       │   ├── Bank.jsx             # 自助充值 / 退币
│       │   ├── Wallet.jsx           # IndexedDB 钱包
│       │   ├── Withdraw.jsx         # 4-step Steps + α/β useRef + TTL
│       │   ├── Payment.jsx          # 粘贴 token + 预验签 + 双花 409 + 托管
│       │   ├── History.jsx          # 交易历史
│       │   └── Privacy.jsx          # 匿名性说明
│       └── __tests__/
│           └── walletDB.test.js     # 8 用例（前端）
├── docs/
│   ├── REQUIREMENTS.md              # 用例 + 功能/非功能需求
│   ├── DESIGN.md                    # 架构 + 时序 + ER + API
│   ├── IMPLEMENTATION.md           # 本文
│   ├── TESTING.md                  # 用例分类 + 盲性证据 + 双花演示
│   ├── USERGUIDE.md               # 用户使用指南
│   └── openapi.yaml               # Swagger 规范
├── ISOLATION.md                     # 不变量与隔离约定
├── Dockerfile
├── docker-compose.yml
├── render.yaml                      # Render 部署配置
├── package.json                     # concurrently 编排
└── README.md
```

---

## 6. 参考实现与文献

- Chaum, D. (1982). *Blind Signatures for Untraceable Payments*. CRYPTO.
- Schnorr, C.-P. (1989). *Efficient Identification and Signatures for Smart Cards*. CRYPTO.
- RFC 6979 — HMAC-based deterministic nonce generation（概念参考；本系统 k_i 用 CSPRNG 独立随机生成）
- BIP-340 — Schnorr signatures over secp256k1（域分离 tag 设计参考）
- @noble/curves 文档 — https://paulmillr.com/noble/（浏览器可跑、常数时间算术）
- PostgreSQL 事务隔离文档 — https://www.postgresql.org/docs/current/transaction-iso.html
- v3 实施大纲 §2.2 / §2.3 / §3.1 / §3.3 — 本项目协议、状态机、不变量来源
