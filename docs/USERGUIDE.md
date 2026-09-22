# BlindCash 用户操作手册（USERGUIDE）

> 面向银行 / 付款人 / 收款人 三方角色的操作指南
>
> 关联：[README.md](../README.md) | [REQUIREMENTS.md](./REQUIREMENTS.md) | [DESIGN.md](./DESIGN.md)

---

## 目录

- [1. 角色与权限](#1-角色与权限)
- [2. 启动与访问](#2-启动与访问)
- [3. 银行（bank）操作](#3-银行bank操作)
- [4. 付款人（customer）操作](#4-付款人customer操作)
- [5. 收款人（merchant）操作](#5-收款人merchant操作)
- [6. 双花演示路径](#6-双花演示路径)
- [7. 界面友好度设计](#7-界面友好度设计)
- [8. 常见问题](#8-常见问题)

---

## 1. 角色与权限

| 角色 | 可访问页面 | 可访问 API | 初始余额 |
|------|-----------|-----------|----------|
| 银行（系统） | — | 启动时自动初始化密钥对 | — |
| 付款人 customer | `/dashboard` `/bank` `/withdraw` | `/api/auth/*` `/api/withdraw/*` `/api/bank/deposit` `/api/bank/redeem` | 0（需先充值） |
| 收款人 merchant | `/dashboard` `/payment` | `/api/auth/*` `/api/payment` `/api/bank/pubkey` | 0 |

**角色互斥**：注册时选定角色后不可切换；DB 层 `CHECK(role IN ('customer','merchant'))` 约束。

**角色守卫**：

- customer 调 `/api/payment` → 403 FORBIDDEN
- merchant 调 `/api/withdraw/*` → 403 FORBIDDEN
- 未登录调任意受保护路由 → 401 UNAUTHORIZED

---

## 2. 启动与访问

### 2.1 启动命令

```bash
# 1. 安装依赖（前后端）
npm run install:all

# 2. 初始化数据库（首次）
npm run init:db

# 3. 启动开发服务
npm run dev

# 演示模式（cut-and-choose N=10，提速 10 倍）
BC_DEMO_N=10 npm run dev
```

### 2.2 访问入口

| 入口 | URL | 说明 |
|------|-----|------|
| 前端首页 | http://localhost:5174 | 自动跳转到 /login 或 /dashboard |
| 注册页 | http://localhost:5174/register | 选择角色注册 |
| 登录页 | http://localhost:5174/login | 登录后按角色跳转 |
| 健康检查 | http://localhost:4100/api/health | 后端状态 + milestone 标识 |

### 2.3 默认账号策略

**不预置账号**——所有用户需通过 `/register` 自行注册。建议演示账号：

| 用户名 | 密码 | 角色 | 用途 |
|--------|------|------|------|
| alice | Pw12345! | customer | 付款人取款演示 |
| bob | Pw12345! | merchant | 收款人兑付演示 |
| carol | Pw12345! | merchant | 双商户并发双花演示 |

> 密码须满足校验规则：≥8 位且含字母 + 数字 + 特殊字符。

---

## 3. 银行（bank）操作

> 银行是**系统角色**，无人工操作界面。所有动作由后端自动执行。

### 3.1 启动时自动行为

服务启动时执行 [app.js initDatabase()](../backend/src/app.js#L40)：

1. `initSchema()` —— 创建 4 张表（users / bank_keys / withdrawal_sessions / spent_coins）+ 2 个唯一索引
2. `bankKeyService.getOrGenerate()` —— 若 `bank_keys` 表无 singleton 行（id=1）则生成新密钥对；否则读取已有密钥对（避免重生成使旧 token 失效）
3. 控制台输出：`[backend] Bank public key: <33-byte hex>`

### 3.2 银行在 4-move 协议中的角色

| 步骤 | 银行执行 | API 入口 |
|------|----------|----------|
| ① init | 生成 N 个 (k_i, R_i = k_i·G)，存入 session | POST /api/withdraw/init（customer 调用） |
| ② submit | 接收 N 个 (R'_i, e_i)，随机挑 j | POST /api/withdraw/submit（customer 调用） |
| ⑤ reveal | 验证 i ≠ j 的 (α_i, β_i) 构造正确，计算 s_j = (k_j + e_j·x) mod n | POST /api/withdraw/reveal（customer 调用） |
| ⑦ cancel | 退款 balance += amount，session 状态推进为 cancelled | POST /api/withdraw/cancel（customer 调用） |

### 3.3 银行在支付环节的角色

| 步骤 | 银行执行 | API 入口 |
|------|----------|----------|
| 预验签 | — | 客户端本地调用 `verifySig`（不经银行） |
| 兑付 | `BEGIN IMMEDIATE`：SELECT serial → 已存在则 409；否则 INSERT spent_coins + UPDATE merchant.balance | POST /api/payment（merchant 调用） |

### 3.4 银行密钥安全边界

⚠ **明文存 DB 仅为教学妥协**（详见 [ISOLATION.md §五](../ISOLATION.md)）：

- `bank_keys.private_key` 明文存储
- 测试**不应**通过读 `private_key` 伪造签名来"证明"任何安全性
- 生产环境应使用 HSM / TEE / Shamir 分片（密钥安全是另一门课的主题）

---

## 4. 付款人（customer）操作

### 4.1 注册

1. 浏览器访问 http://localhost:5174/register
2. 填写：用户名（如 `alice`）、密码（如 `pw123`）、角色选 **customer**
3. 提交后自动跳转 /login
4. 登录后跳转 /dashboard，可见初始余额 0；顶部出现"充值" CTA，点击进入 /bank

### 4.2 充值（/bank）

> Phase 1 新增：新用户注册时余额为 0，必须先通过 /bank 充值才能取款。

进入 `/bank`，可见两个 Tab：

#### Tab 1：充值（deposit）

1. 在 InputNumber 中输入充值金额（校验：1 ≤ amount ≤ 1000，单次上限 1000 BC；24h 滚动累计上限 5000 BC）
2. 点击"充值"
3. 后端 POST /api/bank/deposit：模拟外部法币入账，`BEGIN IMMEDIATE` 更新 `users.balance` 与 `bank_reserve.reserve_balance`，并调用 `assertInvariant` 校验
4. 成功后跳回 /dashboard，余额 += amount

#### Tab 2：退币（redeem）

1. 在 InputNumber 中输入退币金额（校验：1 ≤ amount ≤ balance）
2. 点击"退币"
3. 后端 POST /api/bank/redeem：用户将自有 BC 退回银行，`BEGIN IMMEDIATE` 更新 `users.balance` 与 `bank_reserve.reserve_balance`，调用 `assertInvariant`
4. 成功后跳回 /dashboard，余额 -= amount

> **演示流程**：注册（balance=0）→ /bank 充值 100 BC → /withdraw 取款 30 BC → 复制 token → /payment（自身或另一商户）粘贴 token → 预验签 → 提交 → 商户 +30。

### 4.3 取款 4-step 向导

进入 `/withdraw`，可见 antd **Steps** 4 步骤向导：

#### Step 1/4：发起取款

1. 在 InputNumber 中输入金额（校验：1 ≤ amount ≤ balance，超限报错）
2. 点击"开始取款"
3. 后端执行：`BEGIN IMMEDIATE` 扣款 + 生成 N 个 (k_i, R_i) + INSERT session
4. 进入 Step 2/4

> **TTL 提示**：顶部出现 5 分钟倒计时（1Hz 刷新），过期前未完成则下次 init 自动退款。

#### Step 2/4：客户端构造候选

1. 前端在浏览器调用 `generateBlinders()` 生成 N 对 (α_i, β_i) —— **不离开内存**
2. 调用 `computeBlindedCommitment` 计算 N 个 R'_i 和 e_i
3. 点击"提交候选"
4. POST /api/withdraw/submit，后端随机挑 j 并要求揭示 i ≠ j
5. 进入 Step 3/4

> **盲化因子保护**：α_j / β_j 只存在 `useRef([])`，刷新页面 / 关闭标签页会弹窗警告"将丢失盲化因子"。

#### Step 3/4：揭示 + 反盲化

1. 前端对 i ≠ j 揭示 (α_i, β_i)
2. 后端 `verifyRevealed` 验证 R'_i / e_i 构造正确
3. 后端用 j 的 (R_j, e_j) 计算 s_j = (k_j + e_j·x) mod n
4. 前端调用 `unblindResponse` 计算 s'_j = (s_j + α_j) mod n
5. **即时清空** `blindersRef.current = []`（ISOLATION §三-3）
6. 进入 Step 4/4

#### Step 4/4：展示与复制 token

1. 前端展示 token JSON：
   ```json
   {
     "serial": "32-byte hex",
     "amount": 30,
     "R_prime": "33-byte compressed point hex",
     "s_prime": "32-byte BE hex"
   }
   ```
2. 点击"复制 token"按钮复制到剪贴板
3. 系统提示：将 token 粘贴给 merchant 在 `/payment` 页面完成兑付

### 4.4 取消取款

- 任意 step 中点击顶部"取消取款"按钮
- 后端 `POST /api/withdraw/cancel` 执行：`BEGIN IMMEDIATE` 退款 + session 状态推进为 cancelled
- 前端清空 blindersRef 并回到 Step 0

### 4.5 刷新 / 关闭页面的保护

- `beforeunload` 事件触发：弹窗"将丢失盲化因子，本次取款需重新发起"
- 用户确认离开后 session 仍在后端，5 分钟 TTL 过期后下次 init 自动退款

---

## 5. 收款人（merchant）操作

### 5.1 注册

1. 浏览器访问 http://localhost:5174/register
2. 填写：用户名（如 `bob`）、密码（如 `pw123`）、角色选 **merchant**
3. 登录后跳转 /dashboard，可见余额 0

### 5.2 收款（粘贴 token）

进入 `/payment`，操作流程：

#### Step 1：粘贴 token

1. 将 customer 复制的 token JSON 粘贴到 TextArea
2. 前端 300ms debounce 后自动触发 JSON.parse + cheapFormatCheck

#### Step 2：预验签

1. 前端在浏览器本地调用 `verifySig(s'·G == R' + e'·P)`
2. **预览徽章**显示：
   - ✅ ✓ 验签通过 + 4 字段预览（serial / amount / R' / s'）
   - ❌ ✗ 解析失败 / 验签失败 / 字段缺失
3. 提交按钮在预验签未 ✓ 时**禁用**

#### Step 3：提交存款

1. 点击"提交存款"
2. POST /api/payment，后端 `processPayment` 执行：
   - formatGate（H1）：字符串级校验，拦截畸形 token
   - verifySig：再次曲线级验签（事务外）
   - `BEGIN IMMEDIATE`：SELECT serial → 已存在则 409；否则 INSERT spent_coins + UPDATE merchant.balance
3. 成功 → 商户余额 += amount，UI 显示绿色 ✓ 成功提示
4. 失败 → UI 显示红色错误提示（见 §5.3）

### 5.3 收款错误码与提示

| 状态码 | 错误码 | UI 提示 | 处置 |
|--------|--------|---------|------|
| 400 | MALFORMED_TOKEN | "token 格式不合法" | 检查 JSON 字段是否完整 |
| 400 | SIGNATURE_INVALID | "验签失败，token 已被篡改" | 联系付款人重新取款 |
| 403 | FORBIDDEN | "仅商户可调用此接口" | 检查登录角色 |
| 404 | MERCHANT_NOT_FOUND | "商户账号不存在" | 重新登录 |
| 409 | DOUBLE_SPEND | "双花已检测，token 已被消费" | 不可重复使用同一 token |

### 5.4 双花演示

提交成功后页面出现"再次提交同 token"按钮：

1. 点击该按钮
2. 前端再次 POST /api/payment 同一 token
3. 后端 `BEGIN IMMEDIATE`：SELECT serial → 已存在 → 409 DOUBLE_SPEND
4. UI 显示红色"双花已检测"提示

> **教学文案**：UI 顶部 Alert 显式说明"双花检测的时序不确定——并发提交时由 SQLite 写锁调度，不保证先发起者胜"。

---

## 6. 双花演示路径

### 6.1 单商户重试演示（简单路径）

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | alice/customer 注册 + 登录 | balance = 0 |
| 2 | alice 进入 /bank，充值 100 BC | balance = 100 |
| 3 | alice 进入 /withdraw，输入 30，4 步完成取款 | balance = 70，复制 token |
| 4 | bob/merchant 注册 + 登录 | balance = 0 |
| 5 | bob 进入 /payment，粘贴 token，预验签 ✓ | 提交按钮可用 |
| 6 | bob 点击"提交存款" | balance = 30，绿色成功提示 |
| 7 | bob 点击"再次提交同 token" | 409 双花已检测 |

### 6.2 双商户并发演示（高级路径）

| 步骤 | 操作 | 预期 |
|------|------|------|
| 1 | alice 注册 + /bank 充值 100 + 完成 30 取款，复制 token | balance = 70 |
| 2 | bob/merchant 登录，在标签页 A 粘贴 token | 预验签 ✓ |
| 3 | carol/merchant 登录（另一标签页 B）粘贴同一 token | 预验签 ✓ |
| 4 | 在 A 与 B 几乎同时点击"提交存款" | 一个 200 一个 409 |
| 5 | 检查 A、B 余额 | 一个 balance=30，一个 balance=0 |

> **时序说明**：SQLite `BEGIN IMMEDIATE` 写锁互斥，第二个请求阻塞等第一个 COMMIT 后再继续，必然检测到 serial 已存在返回 409。具体谁赢由 OS 调度决定，UI 文案显式说明"不保证先发起者胜"。

### 6.3 截图占位

```
[截图占位 1] /withdraw Step 4/4 token JSON 展示与复制按钮
路径：docs/assets/withdraw-step4.png

[截图占位 2] /payment TextArea 粘贴 + ✓ 预验签徽章 + 4 字段预览
路径：docs/assets/payment-preview.png

[截图占位 3] /payment 提交成功后余额 +30 + "再次提交同 token"按钮
路径：docs/assets/payment-success.png

[截图占位 4] /payment 双花 409 红色提示
路径：docs/assets/double-spend-409.png
```

---

## 7. 界面友好度设计

> 对应评分标准"界面优美，人际交互友好 +10 分"。

### 7.1 视觉规范

- **antd 6** 设计系统：统一间距、圆角、字体、按钮样式
- **原生 CSS / antd token**：自定义布局与主题微调（`index.css` + ConfigProvider theme token）
- **role-gated 菜单**：customer 主菜单只见"取款"，merchant 主菜单只见"收款"，避免误操作
- **状态色规范**：绿色 ✓ 成功、红色 ✗ 错误、橙色 ⏳ 倒计时

### 7.2 交互反馈

| 反馈类型 | 实现 | 触发 |
|----------|------|------|
| 即时预验签 | useEffect + 300ms debounce | merchant 粘贴 token 后自动触发 |
| 提交按钮联动 | 预验签未 ✓ 时禁用 | 防止无效 POST |
| TTL 倒计时 | useState + 1Hz setInterval + 红色告警 | customer 取款向导顶部显示 |
| 错误码映射 | mapApiError 函数覆盖所有错误码 | API 返回非 200 时友好中文提示 |
| 取消按钮 | 顶部"取消取款"始终可见 | customer 任意 step 可取消 |
| 双花重试 | "再次提交同 token"按钮 | 提交成功后出现 |

### 7.3 安全提示

| 提示 | 位置 | 目的 |
|------|------|------|
| beforeunload 警告 | Withdraw.jsx | 防止用户刷新丢失 α/β |
| 角色守卫 403 提示 | 任意越权调用 | 防止 customer 调 /payment |
| 余额不足提示 | Withdraw InputNumber | 防止超额取款 |
| 双花时序说明 Alert | Payment.jsx 顶部 | 教学澄清"不保证先发起者胜" |
| 演示模式警告 | BC_DEMO_N=10 启动时 | 防止生产误用 |

### 7.4 可访问性

- 所有按钮带 aria-label
- 表单字段带 label
- 错误提示用 antd Alert（role="alert"）
- 颜色 + 图标双重编码（不依赖单一颜色，色盲友好）

---

## 8. 常见问题

### Q1：为什么 α/β 不存 sessionStorage？

A：α_j / β_j 是盲签协议的核心盲化因子，一旦泄露银行可将最终 token 关联回取款会话，破坏盲性。useRef 只保证 React 不序列化它；真正的进程隔离依赖浏览器同源策略。详见 [ISOLATION.md §七](../ISOLATION.md)。

### Q2：为什么双花测试不假设先发起者胜？

A：SQLite 写锁互斥的时序由 OS 调度决定，无法预测。本项目 UI 显式说明"不保证先发起者胜"。测试用 `Promise.all` + `.sort()` 检查结果集，不假设具体 200/409 归属。详见 [docs/TESTING.md §3](./TESTING.md)。

### Q3：演示模式 N=10 安全吗？

A：N=10 时作弊成功率 10%（远高于 N=100 的 1%），仅用于教学演示提速。生产环境必须 N=100。`config/bank.js` 与 `docs/IMPLEMENTATION.md §2.4` 显式标注此约束。

### Q4：为什么 clientBuild.test.js 保留 `shell: true`？

A：Windows 上 `npx` 实际是 `npx.cmd` 批处理脚本，Node 的 `child_process.spawn` 在 Windows 无法直接执行 .cmd 文件，必须通过 shell 转发。args 全部硬编码无注入面，DeprecationWarning 是非阻塞噪声。详见 [docs/IMPLEMENTATION.md §2.9](./IMPLEMENTATION.md)。

### Q5：如何验证盲性？

A：本项目提供 3 个实证测试（详见 [docs/TESTING.md §2](./TESTING.md)）：

1. 1000-trial Shannon 熵 ≥ 200 bits（理论 264000 bits，极度保守阈值）
2. 1000-trial 作弊成功率 [50, 200]/1000（理论 100 ± 9.5）
3. token-session 不可链接：用 session B 的 (R, e, s) 与 session A 的 (R', s') 计算 verifySig 必失败

### Q6：如何重启服务保持密钥不变？

A：`bankKeyService.getOrGenerate()` 启动时检查 `bank_keys` 表：

- 第一次启动：表为空 → 生成新密钥对 → INSERT singleton 行
- 后续启动：表有行 → 直接读取 → **不重生成**

这样重启不会使旧 token 失效。重启后控制台输出与上次相同的 `Bank public key` 即正确。

### Q7：为什么不预置 admin 账号？

A：本项目无 admin 角色——只有 customer 与 merchant 两类互斥角色。所有账号需通过 `/register` 自行注册。详见 [docs/REQUIREMENTS.md](./REQUIREMENTS.md) UC-1。
