# BlindCash 不变量与隔离约定（ISOLATION）

> 来源：v3 实施大纲 §3.3。本文件是后续里程碑（M2-M7）实现与测试的**硬约束**：
> 任何代码改动若违反下列不变量，必须在该次提交的 commit message 中显式说明
> 理由，并在 review 时重点核查。
>
> **M7 阶段一更新**：每条不变量下方新增"落地证据"小节，标注实现位置与测试用例，
> 覆盖 M1-M7 全链路。详见 `docs/IMPLEMENTATION.md`、`docs/TESTING.md`。

---

## 一、余额流转不变量（balance flow）

1. **customer.balance 只被取款与托管退款流程扣减/增加**
   - `POST /withdraw/init` 时 `balance -= amount`（在 `runImmediateTx` 事务内）。
   - `POST /withdraw/cancel` 与过期懒清理时 `balance += amount`（退款，可加回）。
   - `POST /payment` 与 `POST /escrow/lock` **绝不触碰** customer.balance（顾客不直接收款）。
   - `POST /escrow/cancel` 与过期托管懒清理时 `balance += amount`（退款，可加回）。

2. **merchant.balance 只被支付与托管结算流程增加**
   - `POST /payment` 验签通过且未双花时 `merchant.balance += amount`。
   - `POST /escrow/confirm` 时 `merchant.balance += amount`（托管结算）。
   - `/withdraw/*` **绝不触碰** merchant.balance（商户不取款）。

> 上述流转不依赖角色锁。M7 角色解锁后 `/withdraw/*` 与 `/api/payment` 对任何
> 已登录用户开放，余额守恒由**密码学验签 + `spent_coins` 唯一约束 + 用户身份隔离**
> 共同保证：收款/退款目标账户由 token 的 `deposited_to`（托管单 `merchant_id`）与
> 服务端注入的当前用户身份决定，而非路由级别的 `requireRole`。

**落地证据**：

- 实现位置：
  - `backend/src/routes/withdrawal.js` —— `withdrawGuard = [authenticateJWT]`（M7 角色解锁，仅要求登录）
  - `backend/src/routes/payment.js` —— `depositGuard = [authenticateJWT]`（M7 角色解锁，仅要求登录）
  - `backend/src/services/withdrawalService.js` —— `initWithdrawal` / `cancelWithdrawal` / `lazyCleanupExpiredSessions` 均通过 `runImmediateTx` 原子操作 `users.balance`
  - `backend/src/services/paymentService.js` —— `processPayment` 中 `UPDATE users SET balance = balance + ? WHERE id = ?` 只针对 token 指定的收款商户
  - `backend/src/services/escrowService.js` —— `confirmEscrow` 结算给 `escrow.merchant_id`；`cancelEscrow` / 过期懒清理退款给 `escrow.customer_id`
- 测试覆盖：
  - `withdrawal.test.js` —— "M4: 4-move happy path" 验证 init 后 customer.balance 减少
  - `withdrawal.test.js` —— "M4: [必测#3] expired session lazy-cleanup refund" 验证退款恢复 balance
  - `withdrawal.test.js` —— "M4: cancel flow" 验证 cancel 后 balance 加回
  - `payment.test.js` —— "M5: happy path" 验证 merchant.balance 增加 + customer.balance **未被 payment 触碰**
  - `payment.test.js` —— "M5/M7: role guard unlocked + authentication" 验证 customer 调 `/payment` → 200、无 token 调 `/payment` → 401
  - `escrow.test.js` —— "1. 正常闭环…商户入账且不变量守恒" 与 "6. 协商撤销/退款…法币返还顾客账户且不变量守恒" 验证托管结算/退款流转
  - `integration.test.js` —— "M7 · full end-to-end" E2E 验证 balance 流转完整闭环

---

## 二、盲化因子隔离不变量（blindness）

3. **`withdrawal_sessions.candidates` 不存储 α_i / β_i**
   - 4-move 协议中，被签名候选 j 的 α_j / β_j 永不离开用户本地。
   - submit 阶段 API 若收到 α/β 字段 → 直接 400（API 层防御）。
   - reveal 阶段只接收 i ≠ j 的 (α_i, β_i)，且仅用于一次性验证后丢弃。
   - 后果：银行无法反推 (R'_j, e'_j)，token 兑付时不可链接到用户 → 盲性保持。

**落地证据**：

- 实现位置：
  - `backend/src/services/withdrawalService.js` —— `submitCandidates` 显式拒绝任何携带 `alpha` / `beta` 字段对索引 j 的 payload（400 BLINDERS_LEAKED）；`revealAndSign` 只接收 i ≠ j 的 (α_i, β_i)
  - `backend/src/models/schema.sql` —— `withdrawal_sessions.candidates` 列注释明确 "JSON array (no α_i/β_i!)"
  - `backend/src/crypto/server/cutAndChoose.js` —— `verifyRevealed` 用 (α_i, β_i) 验证 R'_i / e_i 构造正确性，验证完即丢弃（不持久化）
  - `frontend/src/pages/Withdraw.jsx` —— `blindersRef = useRef([])` 仅 React 内存；unblind 成功后 `blindersRef.current = []` 即时清空；beforeunload 守卫防刷新
- 测试覆盖：
  - `withdrawal.test.js` —— "M4: [必测#1] blindness invariant 3 — α/β must not leave user device"（3 用例：submit 携带 α_j → 400、reveal 携带错误索引 α_j → 400、commit 后查 candidates JSON 不含 α_j/β_j）
  - `cutAndChoose.test.js` —— "M2 · BLINDNESS EVIDENCE"（3 用例：1000-trial Shannon 熵 ≥ 200 bits、token-session 不可链接、pickRandomJ 分布均匀）
  - `schnorrBlind.test.js` —— "correctness: blind → sign → unblind → verify" 验证协议正确性作为盲性前提

---

## 三、会话与 nonce 隔离不变量（session & nonce）

4. **每用户同时最多 1 个 status ∈ {pending, submitted} 的 session**
   - `POST /withdraw/init` 前必须无活跃 session（或先清理该用户过期 session）。
   - DB 层以 `user_id` + `status` 查询保证；新 init 若检测到活跃 session → 409。

5. **每个 session 独立生成 N 个新 k_i，绝不复用历史 session 的 k**
   - init 时一次性生成 N 个随机 k_i，存于 session 内部状态。
   - 与 nonce 重用防护对齐：复用 k 等价于私钥泄露（Schnorr 安全性崩塌）。
   - 测试覆盖：同用户两次取款的 k 集合无交集。

**落地证据**：

- 实现位置：
  - `backend/src/models/schema.sql` —— `idx_ws_active_per_customer` 部分唯一索引：`CREATE UNIQUE INDEX ... ON withdrawal_sessions(customer_id) WHERE status IN ('pending','submitted')`，DB 层铁律
  - `backend/src/services/withdrawalService.js` —— `initWithdrawal` 服务层先查 active session，存在则抛 409 ACTIVE_SESSION_EXISTS（DB 索引作为 defense-in-depth）
  - `backend/src/services/withdrawalService.js` —— `initWithdrawal` 一次性生成 N 个 `randomScalar()` 作为 k_i（`crypto/server/curve.js` 的 `randomScalar` 用 `@noble/secp256k1` 的 constant-time 算术）
- 测试覆盖：
  - `withdrawal.test.js` —— "M4: [必测#2] session uniqueness invariant 4"（2 用例：服务层第二次 init → 409、DB 层唯一索引在服务层失效时仍能抓到 race）
  - `withdrawal.test.js` —— "M4: validation — second init while active → 409"
  - `integration.test.js` —— "M7 · expired session lazy-cleanup"（2 用例：refund on next init、refund on next submit）
  - `cutAndChoose.test.js` —— "M2 · cutAndChoose.js — verifyAllRevealed" 验证 N 个 k_i 一次性生成

---

## 四、双花检测不变量（double-spend）

6. **`spent_coins.serial` UNIQUE + `token_hash` 边角防护**
   - Payment 时 `runImmediateTx` 原子执行：`SELECT serial` → 已存在则 409；否则
     `INSERT(serial, amount, deposited_to, token_hash)` + `UPDATE merchant.balance`。
   - `token_hash = SHA256(serial ‖ R' ‖ s')` 防同一 token 不同 serial 的边角情况。

**落地证据**：

- 实现位置：
  - `backend/src/models/schema.sql` —— `spent_coins` 表：`serial BLOB PRIMARY KEY` + `idx_sc_token_hash` 唯一索引
  - `backend/src/services/paymentService.js` —— `processPayment` 用 `runImmediateTx(() => { SELECT serial → 409 or INSERT + UPDATE })` 原子操作；`computeTokenHash` 用 `Buffer.concat([serialBytes, RPrimeBytes, sPrimeBytes])` 字节级拼接（H2 防大小写歧义）
  - `backend/src/services/paymentService.js` —— `verifySig` 在事务**外**执行（只读曲线运算无锁），事务只包裹写动作（教授 H3 铁律）
- 测试覆盖：
  - `payment.test.js` —— "M5: [H3] double-spend vs retry semantics"（4 用例：同商户重试 → 409、双商户并发同 token → 200+409、token_hash 大小写归一、跨用户 token 拒绝）
  - `payment.test.js` —— "M5: [H1] malformed token format gate → 400"（4 用例：serial 63 hex → 400、R' 前缀 04 → 400、s' 63 hex → 400、amount=0 → 400）
  - `integration.test.js` —— "M7 · concurrent double-spend across two merchants" 用 `Promise.all` + `.sort()` 验证并发场景（不假设先发起者胜）
  - `integration.test.js` —— "M7 · cross-user — A's token cannot be deposited to merchant who is not the payee"

---

## 五、密钥安全边界声明（out-of-scope）

7. **银行私钥明文存 DB 仅为教学演示，密钥安全是独立维度**
   - `bank_keys.private_key` 明文存储是显式妥协（生产应加密/HSM）。
   - **测试不应通过读 `bank_keys.private_key` 伪造签名来"证明"任何安全性**：
     那只证明了"密钥泄露则系统崩溃"这一常识，不构成对协议本身的攻击。
   - 答辩话术：盲签名协议的安全假设是"签名密钥不泄露"；密钥保护是另一门课
     （密钥管理 / HSM / TEE）的主题，本课程不展开。

   **Phase 6.1 扩展：多面额密钥结构（v6 §四 6.1）**
   - `bank_keys` 表已从 Phase 0 的 `CHECK(id=1)` 单行表重建为多行表
     （迁移 005 去掉 `CHECK(id=1)`，支持密钥轮换；迁移 007 增加 `denomination` 列）。
   - 面额集合 `DENOMINATIONS = [1, 5, 10, 50, 100]`（`backend/src/config/bank.js`），
     不同面额用独立签名密钥——这是 Phase 6.3 匿名集按面额分组的前提。
   - **每个 `(denomination, status='active')` 对最多一把密钥**：迁移 007 的
     partial unique index `idx_bk_active_denom ON bank_keys(denomination) WHERE status = 'active'`
     在 DB 层铁律保证。密钥轮换时旧密钥先 `status='retired'`（脱离 partial index范围）
     再 INSERT 新 `status='active'` 行，两步不冲突。
   - 取款时按面额选 denom，从 `GET /api/bank/pubkeys` 拿对应 denom 的公钥 P 计算盲化承诺；
     token v2 schema 的 `key_id` 对应 `bank_keys.key_version`，支付/退币时反查公钥验签。

   **Phase 6 迁移引入的新列/新约束（007/008/009）**
   - 迁移 008：`withdrawal_sessions.denomination`（reveal 时按 session 行的 denom 选签名密钥）、
     `spent_coins.denomination`（6.3 匿名集按 `(denomination, key_version)` 分组统计）。
     两列均 `DEFAULT 1` 前向兼容旧数据。
   - 迁移 009：`transactions.kind` CHECK 约束扩展为
     `('withdraw','deposit','refund','redeem_split')`，支撑 Phase 6.2 找零兑付流水
     （`/api/bank/redeem-split` 写 `kind='redeem_split'`，与商户收款 `deposit` 区分）。
   - Phase 6.4：`pending_payments` 是**客户端 IndexedDB 状态**，不落服务端 DB，
     不影响任何服务端不变量。客户端钱包在浏览器本地维护待支付队列，提交时才
     调 `/api/payment` 落 `spent_coins`——服务端双花检测不变量 6 不变。

**落地证据**：

- 实现位置：
  - `backend/src/models/schema.sql` —— baseline `bank_keys` 仍保留 `CHECK(id=1)` 注释作为
    教学起点；实际生产 schema 由迁移 005 重建为多行表（`key_version` UNIQUE + `status` + `retired_until`）
  - `backend/src/models/migrations/005_bank_keys_rebuild.sql` —— 去掉 `CHECK(id=1)`，重建为多行表
  - `backend/src/models/migrations/007_bank_keys_add_denomination.sql` —— `denomination` 列 + `idx_bk_active_denom` partial unique index
  - `backend/src/models/migrations/008_add_denomination_to_sessions_and_spent_coins.sql` —— `withdrawal_sessions.denomination` + `spent_coins.denomination`
  - `backend/src/models/migrations/009_transactions_add_redeem_split_kind.sql` —— `transactions.kind` CHECK 扩展 `redeem_split`
  - `backend/src/config/bank.js` —— `DENOMINATIONS = [1, 5, 10, 50, 100]` 常量 + 不变量 7 扩展注释
  - `backend/src/services/bankKeyService.js` —— `getActivePublicKeyByDenom(denom)` / `getActiveKeyVersionByDenom(denom)` / `getDenominationByVersion(key_version)` 按面额路由；`assertKeypairConsistent()` 自检 P == x·G
  - `backend/src/routes/bank.js` —— `GET /api/bank/pubkeys` 返回所有面额 active 公钥映射；`POST /api/bank/redeem-split` Phase 6.2 找零兑付
  - `backend/src/services/paymentService.js` —— `redeemSplit()` INSERT spent_coins 时 `denomination` 列用 `split_denomination`（教学化标记）
  - 任何测试用例**均未**通过读 `bank_keys.private_key` 伪造签名来"证明"任何事
- 测试覆盖：
  - `bankKeyService.test.js`（20 用例）：密钥生成/持久化（首次启动 + 缓存命中 + 二次启动不重生成）、密钥对格式 + 自一致性（P == x·G）、AES-256-GCM 静态加密、按 version 查公钥、rotateKey 轮换（90 天宽限期）、`/api/bank/pubkey` 端点无认证可访问
  - `bankKeyService.test.js` —— "keypair format + self-consistency (P == x·G)" 验证密钥对一致性
  - `bankKeyService.test.js` —— "getOrGenerate(): second boot reads back the SAME keypair" 验证不重新生成

---

## 六、前端密码学边界（v3 风险评估 §一-1）

- 前端只运行 `crypto/client/` 子集（纯函数 + `crypto.getRandomValues`）。
- 前端不依赖 Node 的 `crypto.randomBytes`；`vite-plugin-node-polyfills` 兜底
  处理 Buffer/process 等 Node 全局，使 `@noble/secp256k1` 在浏览器可用。
- 前端预验签只做"33B 压缩点格式 + 前缀 0x02/0x03"校验，完整 `isOnCurve` 留后端。

**落地证据**：

- 实现位置：
  - `backend/src/crypto/client/blinding.js` —— `generateBlinders` 用 `globalThis.crypto.getRandomValues`（Web Crypto），不依赖 Node `crypto.randomBytes`
  - `backend/src/crypto/client/schnorrBlindClient.js` —— `userComputeChallenge` + `verifySig`（预验签）只读曲线运算
  - `frontend/vite.config.js` —— `@crypto` / `@config` / `@utils` alias 跨边界导入，`vite-plugin-node-polyfills` 兜底 Buffer/process 全局，`server.fs.allow: ['..']` 允许 vite 服务 backend/ 下的浏览器可跑子集
  - `frontend/src/pages/Payment.jsx` —— useEffect 300ms debounce 调用 client `verifySig` 做预验签，提交前必 ✓ 通过
- 测试覆盖：
  - `clientBuild.test.js`（4 用例）：`vite build 0 errors`、`crypto/client/* 在 happy-dom 下能调用`
  - `clientBuild.test.js` —— "vite bundle-ability of crypto/client/*" 验证浏览器可打包
  - `clientBuild.test.js` —— "crypto/client/* runs under happy-dom (browser env)" 验证浏览器运行时

---

## 七、α/β 内存隔离不变量（M6 教授风险 #3）

8. **α_j / β_j 只存在前端 `useRef` 内存，绝不序列化到 sessionStorage**
   - `Withdraw.jsx` 中 `const blindersRef = useRef([])` —— 用 useRef 而非 useState：useRef 不会触发重渲染，且 React 不会在 dev 工具中序列化它
   - unblind 成功后立即 `blindersRef.current = []` 清空
   - `sessionActiveRef` + `beforeunload` 事件：用户刷新 / 关闭标签页时弹窗警告"将丢失盲化因子，本次取款需重新发起"
   - sessionStorage 只存 user 信息 + JWT token，**绝不**存 α/β

> **caveat（写入 docs/IMPLEMENTATION.md §2.3）**：
> useRef 仅保证 α/β 不被 React 序列化；它**不是**进程隔离机制。真正的"α/β 永不离开
> 用户设备"假设依赖浏览器同源策略 + 进程隔离。教学语境下可接受：同一浏览器不同
> 标签页是独立 JS realm，α/β 不跨标签页泄露（支撑双商户双标签页双花演示）；但若用户
> 打开 DevTools 手动读取 `blindersRef.current` 则可拿到 α/β，这是"用户自己攻击自己"，
> 不构成对协议的攻击。生产级隔离需 Web Worker / WASM / TEE，超出本课程范围。

**落地证据**：

- 实现位置：
  - `frontend/src/pages/Withdraw.jsx` —— `useRef([])` 声明、`sessionActiveRef` + `beforeunload` 监听、unblind 后 `blindersRef.current = []`
  - `frontend/src/context/AuthContext.jsx` —— `sessionStorage.setItem('bc_user', ...)` 只存 user 信息，无 α/β 字段
- 测试覆盖：
  - 客户端代码由 `clientBuild.test.js` 保证可打包可运行
  - 服务端由 `withdrawal.test.js` 的"M4: [必测#1] blindness invariant 3"保证后端 API 主动拒绝任何 α/β 字段（defense-in-depth）
  - 手动 E2E 演示：见 `docs/TESTING.md` §3.2，验证刷新页面后 session 不可继续

---

## 八、原子写事务不变量（runImmediateTx）

9. **所有涉及余额变动的写操作必须包裹在 `runImmediateTx` 中**
   - PostgreSQL 单连接事务（`BEGIN` → 操作 → `COMMIT`），通过 `pg.Pool.connect()` 独占一个连接执行，避免连接池跨连接导致的事务分裂
   - 任何 throw 自动 `ROLLBACK`，确保 merchant.balance 与 spent_coins、customer.balance 与 session 状态永不分裂
   - `verifySig` 等只读曲线运算在事务**外**执行，避免事务持有期间进行 ms 级曲线运算降低吞吐（教授 H3 铁律）

**落地证据**：

- 实现位置：
  - `backend/src/models/db.js` —— `runImmediateTx(fn)` 函数：从连接池取单连接 → `BEGIN` → `fn(txDb)` → `COMMIT`，throw → `ROLLBACK`，finally `client.release()`
  - `backend/src/services/withdrawalService.js` —— `initWithdrawal` / `cancelWithdrawal` / `lazyCleanupExpiredSessions` 三个写路径全部包裹
  - `backend/src/services/paymentService.js` —— `processPayment` 包裹 SELECT serial → INSERT + UPDATE
- 测试覆盖：
  - `payment.test.js` —— "M5: [H3] double-spend vs retry semantics" 验证双商户并发同一 token 时 PostgreSQL `spent_coins.serial` UNIQUE 约束互斥：一个 200 一个 409
  - `integration.test.js` —— "M7 · concurrent double-spend across two merchants" 用 `Promise.all` 触发真实并发，验证原子性
  - `withdrawal.test.js` —— "M4: [必测#2] session uniqueness invariant 4" 验证并发 init 时唯一索引能抓到 race

---

## 九、担保托管状态机不变量（Phase 7 escrow）

10. **`payment_escrows` 两阶段托管状态机 + 确认权限制 + 防抢兑 + 退款守恒**
   - 状态机：`created → locked → committed`（正常闭环）或 `created → cancelled`
     （商户撤销）、`locked → cancelled`（退款）、`created/locked → expired`（超时）。
   - `created` 仅商户可撤销；`locked` 仅锁定该单的顾客本人可 confirm（商户无权自证结算）。
   - Lock 阶段在事务内先向 `spent_coins` 写入占位（`deposited_to` 绑定 `escrow.merchant_id`），
     使老接口 `POST /api/payment` 与新接口 `POST /escrow/lock` 均无法对同一 token 抢兑。
   - confirm 结算给 `escrow.merchant_id` 余额并增加 `total_redeemed`；cancel/expired 退款给
     `escrow.customer_id` 法币余额并减少 `total_issued`；token 永久作废防信息泄漏。
   - 全流程在 `runImmediateTx` 单连接事务内执行，事务末尾 `assertInvariant` 断言准备金守恒。

**落地证据**：

- 实现位置：
  - `backend/src/services/escrowService.js` —— `createEscrow`（服务端注入 `merchant_id`）、`lockToken`（防抢兑占位 `spent_coins`）、`confirmEscrow`（仅 `customer_id` 可确认）、`cancelEscrow`（`created` 仅商户可撤销；`locked` 商户可退 / 顾客超时可退）、`lazyCleanupExpiredEscrows`（超时自动退款）
  - `backend/src/models/schema.sql` —— `payment_escrows` 表含 `merchant_id` / `customer_id` / `challenge` / `serial` / `token_hash` / `status` / `expires_at`
  - `backend/src/services/bankReserveService.js` —— `assertInvariant` 中 `(total_issued − total_redeemed)` 天然涵盖 locked 在途托管资金（token 仍在发行总量中、`spent_coins` 已占位），confirm 时 `total_redeemed` 增加、cancel 时 `total_issued` 减少，等式守恒
- 测试覆盖（`escrow.test.js`，6 用例）：
  - "1. 正常闭环：商户创建收款单 → 顾客 lock 资金 → 顾客 confirm 收货 → 商户入账且不变量守恒"
  - "2. 权限防线：商户自身或中间人无权 confirm 结算"
  - "3. 防中间人抢兑：窃取 token + challenge 无法存入攻击者自己账户"
  - "4. 原接口防绕过：一旦 token 被锁定，老接口 POST /api/payment 无法抢兑"
  - "5. 一币多锁拦截：同一个 Token 无法同时锁定到两个不同的收款单"
  - "6. 协商撤销/退款：商户可主动退款，法币返还顾客账户且不变量守恒"
