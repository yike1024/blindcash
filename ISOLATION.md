# BlindCash 不变量与隔离约定（ISOLATION）

> 来源：v3 实施大纲 §3.3。本文件是后续里程碑（M2-M7）实现与测试的**硬约束**：
> 任何代码改动若违反下列不变量，必须在该次提交的 commit message 中显式说明
> 理由，并在 review 时重点核查。

---

## 一、余额流转不变量（balance flow）

1. **customer.balance 只被 `/withdraw/*` 流程扣减**
   - `POST /withdraw/init` 时 `balance -= amount`（在 BEGIN IMMEDIATE 内）。
   - `POST /withdraw/cancel` 与过期懒清理时 `balance += amount`（退款，可加回）。
   - `POST /payment` **绝不触碰** customer.balance（顾客不直接收款）。

2. **merchant.balance 只被 `/payment` 流程增加**
   - `POST /payment` 验签通过且未双花时 `merchant.balance += amount`。
   - `/withdraw/*` **绝不触碰** merchant.balance（商户不取款）。

> 上述两条由 `requireRole` 中间件 + 路由分区共同保证：`/withdraw/*` 仅
> `customer` 可调，`/payment` 仅 `merchant` 可调。

---

## 二、盲化因子隔离不变量（blindness）

3. **`withdrawal_sessions.candidates` 不存储 α_i / β_i**
   - 4-move 协议中，被签名候选 j 的 α_j / β_j 永不离开用户本地。
   - submit 阶段 API 若收到 α/β 字段 → 直接 400（API 层防御）。
   - reveal 阶段只接收 i ≠ j 的 (α_i, β_i)，且仅用于一次性验证后丢弃。
   - 后果：银行无法反推 (R'_j, e'_j)，token 兑付时不可链接到用户 → 盲性保持。

---

## 三、会话与 nonce 隔离不变量（session & nonce）

4. **每用户同时最多 1 个 status ∈ {pending, submitted} 的 session**
   - `POST /withdraw/init` 前必须无活跃 session（或先清理该用户过期 session）。
   - DB 层以 `user_id` + `status` 查询保证；新 init 若检测到活跃 session → 409。

5. **每个 session 独立生成 N 个新 k_i，绝不复用历史 session 的 k**
   - init 时一次性生成 N 个随机 k_i，存于 session 内部状态。
   - 与 nonce 重用防护对齐：复用 k 等价于私钥泄露（Schnorr 安全性崩塌）。
   - 测试覆盖：同用户两次取款的 k 集合无交集。

---

## 四、双花检测不变量（double-spend）

6. **`spent_coins.serial` UNIQUE + `token_hash` 边角防护**
   - Payment 时 `BEGIN IMMEDIATE` 原子执行：`SELECT serial` → 已存在则 409；否则
     `INSERT(serial, amount, deposited_to, token_hash)` + `UPDATE merchant.balance`。
   - `token_hash = SHA256(serial ‖ R' ‖ s')` 防同一 token 不同 serial 的边角情况。

---

## 五、密钥安全边界声明（out-of-scope）

7. **银行私钥明文存 DB 仅为教学演示，密钥安全是独立维度**
   - `bank_keys.private_key` 明文存储是显式妥协（生产应加密/HSM）。
   - **测试不应通过读 `bank_keys.private_key` 伪造签名来“证明”任何安全性**：
     那只证明了“密钥泄露则系统崩溃”这一常识，不构成对协议本身的攻击。
   - 答辩话术：盲签名协议的安全假设是“签名密钥不泄露”；密钥保护是另一门课
     （密钥管理 / HSM / TEE）的主题，本课程不展开。

---

## 六、前端密码学边界（v3 风险评估 §一-1）

- 前端只运行 `crypto/client/` 子集（纯函数 + `crypto.getRandomValues`）。
- 前端不依赖 Node 的 `crypto.randomBytes`；`vite-plugin-node-polyfills` 兜底
  处理 Buffer/process 等 Node 全局，使 `elliptic` 在浏览器可用。
- 前端预验签只做“33B 压缩点格式 + 前缀 0x02/0x03”校验，完整 `isOnCurve` 留后端。
