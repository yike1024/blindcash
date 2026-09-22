// crypto/client/protocolConstants.js — 前端密码学子集可安全引用的协议常量
//
// 为什么存在：前端（M6 Withdraw.jsx 等）在构造盲化候选时需要 TOKEN_DOMAIN_TAG
// 计算 e' = H(tag ‖ R' ‖ serial ‖ amount ‖ P)。此前前端通过 vite 别名 @config
// 直接 import 后端 config/bank.js —— 但 bank.js 依赖 process.env（后端语义），
// 被 vite-plugin-node-polyfills 注入 process shim 后，从 backend 目录解析
// 'vite-plugin-node-polyfills/...' 会失败（该包只存在于 frontend/node_modules）。
//
// 修复：把前后端共用的纯协议常量下沉到这里（零 Node 依赖，浏览器可直接运行），
// 后端 config/bank.js 从这里 import 并 re-export（保持后端 API 不变），前端
// 从 @crypto/client/protocolConstants.js 引用 —— 单一权威源，不再跨目录依赖
// 后端配置。
//
// 注意：SESSION_TTL_MS 不入此文件 —— TTL 是后端可配置项（BC_SESSION_TTL_MS
// 可覆盖），前端倒计时用后端 /withdraw/init 响应返回的 ttl_ms（单源）。

/**
 * 域分离标签：H(tag ‖ data)，防止同一 (R', serial, amount) 元组跨协议/跨链重用。
 * 修改此值会使所有已签发 token 失效（见 config/bank.js 注释）。
 */
export const TOKEN_DOMAIN_TAG = 'blindcash-v1';
