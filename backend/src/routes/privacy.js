// routes/privacy.js — Phase 6.3: 匿名集分析端点
//
// POST /api/privacy/report — 需 JWT
//   body: { tokens: [{ key_id: number }, ...] }
//   returns: { report: [...], limitations: [...] }
//
// 服务端不知道用户持有哪些 token（钱包在客户端 IndexedDB），所以前端
// 把 token 列表（只含 key_id）发到本接口，服务端用 key_id 反查 denom，
// 再统计 spent_coins 中相同 (denom, key_version) 的数量作为匿名集大小。
//
// **隐私设计**：前端只发 key_id（密钥版本号），不发 serial/R'/s'。
// key_id 本身不是敏感信息——它是银行公钥的版本号，任何人都能从
// /api/bank/pubkeys 拿到。发 key_id 让服务端反查 denom，不泄露 token 内容。

import { Router } from 'express';
import { authenticateJWT } from '../middleware/auth.js';
import { computeAnonymityReport } from '../services/privacyService.js';

const router = Router();

router.post('/report', authenticateJWT, (req, res) => {
  try {
    const { tokens } = req.body || {};
    if (!Array.isArray(tokens)) {
      return res.status(400).json({
        error: 'VALIDATION_ERROR',
        message: 'tokens must be an array of { key_id: number }',
      });
    }
    const result = computeAnonymityReport(tokens);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

export default router;
