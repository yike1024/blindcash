// pages/Withdraw.jsx — M6 step 1: customer 4-move 取款向导
//
// v3 §5 M6 step 1 + professor's 5 must-haves:
//   🔴 α/β only live in memory (useRef) — refresh/closes page → 取款作废.
//      → 顶部 Alert 警示 + beforeunload 拦截 + "取消取款"按钮全程可见.
//   🟢 取款金额 ≤ balance 前端先拦 (后端 400 兜底).
//   🟢 TTL 倒计时 (init 时间 + SESSION_TTL_MS=5min) 显示给用户.
//
// 4-step state machine (antd Steps):
//   step 0: 输入金额 → POST /api/withdraw/init → { session_id, R[], N }
//   step 1: 客户端构造 N 个候选 (α/β 仅在 useRef) → POST /api/withdraw/submit → { j }
//   step 2: 构造 revealed (i≠j) → POST /api/withdraw/reveal → { s_j } → unblind → s'
//   step 3: 展示 token { serial, amount, R_prime, s_prime } + 复制按钮
//
// ISOLATION §三-3: α_j / β_j for the signed candidate j NEVER leave the device.
//   We store blinders in a useRef (NOT useState) so they don't appear in any
//   React devtools state snapshot, never get serialized to sessionStorage, and
//   are GC'd the moment the page unloads. The submitted `candidates` payload
//   contains only { e, R_prime, serial } — the same shape the test suite uses.

import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card, Steps, Form, InputNumber, Button, Alert, Space, Typography,
  Descriptions, Tag, message, Result, Spin, Statistic, Row, Col, Input,
} from 'antd';
import { CopyOutlined, ExclamationCircleOutlined } from '@ant-design/icons';

import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';
import { generateBlinders, computeBlindedCommitment, unblindResponse } from '@crypto/client/blinding.js';
import { hashToScalar } from '@crypto/server/hashToScalar.js';
import { modN } from '@crypto/server/curve.js';
import { bytesToHex, hexToBytes } from '@utils/hex.js';
import { TOKEN_DOMAIN_TAG, SESSION_TTL_MS } from '@config/bank.js';

const { Title, Text, Paragraph } = Typography;

// ── helpers ────────────────────────────────────────────────────────────
// bigint → 64-hex (zero-padded); used for e / alpha / beta / s' serialization.
function scalarToHexFixed(s) {
  let h = s.toString(16);
  while (h.length < 64) h = '0' + h;
  if (h.length > 64) h = h.slice(h.length - 64); // mod n already applied upstream
  return h;
}
function hexToScalarFixed(hex) {
  let v = 0n;
  for (let i = 0; i < hex.length; i++) {
    v = (v << 4n) | BigInt(parseInt(hex[i], 16));
  }
  return v;
}

// Error code → human-readable Chinese message.
// err.response.data.error is the bank's WithdrawalError code; fall back to
// data.message if code is missing (e.g. express-validator VALIDATION_ERROR).
function mapApiError(err, fallback = '操作失败') {
  const code = err?.response?.data?.error;
  const srvMsg = err?.response?.data?.message;
  switch (code) {
    case 'ACTIVE_SESSION_EXISTS':
      return '已有进行中的取款会话。请等 5 分钟过期或联系管理员重置后再试。';
    case 'INSUFFICIENT_BALANCE':
      return '余额不足。';
    case 'INVALID_AMOUNT':
      return '取款金额必须为正整数。';
    case 'SESSION_NOT_FOUND':
      return '会话不存在或不属于当前用户。';
    case 'SESSION_EXPIRED':
      return '会话已过期，余额已退还，请重新开始取款。';
    case 'WRONG_STATUS':
      return `会话状态错误：${srvMsg ?? ''}`;
    case 'CANDIDATE_COUNT':
      return '候选数量与服务器期望不符（前端 bug）。';
    case 'INVALID_CANDIDATE':
    case 'INVALID_CANDIDATES':
      return '提交的候选格式不正确（前端 bug）。';
    case 'BLINDER_LEAKED':
      return '提交数据疑似包含 α/β（前端 bug，应永不发生）。';
    case 'SIGNED_CANDIDATE_REVEALED':
      return 'reveal 数据疑似包含 j 索引（前端 bug，应永不发生）。';
    case 'REVEAL_COUNT':
    case 'REVEAL_DUPLICATE':
    case 'REVEAL_INCOMPLETE':
      return 'reveal 索引集合不正确（前端 bug）。';
    case 'CUT_AND_CHOOSE_FAILED':
      return 'cut-and-choose 验证失败：会话已 abort，余额已退还。';
    case 'NOT_CANCELLABLE':
      return '会话已提交，无法取消。';
    case 'VALIDATION_ERROR':
      return `请求参数校验失败：${srvMsg ?? ''}`;
    default:
      return fallback;
  }
}

// Format ms countdown as mm:ss.
function fmtCountdown(ms) {
  if (ms <= 0) return '00:00';
  const total = Math.floor(ms / 1000);
  const m = String(Math.floor(total / 60)).padStart(2, '0');
  const s = String(total % 60).padStart(2, '0');
  return `${m}:${s}`;
}

// ── main component ─────────────────────────────────────────────────────
export default function WithdrawPage() {
  const { user, updateUser } = useAuth();
  const navigate = useNavigate();

  // step: 0..3 (current antd Step)
  const [step, setStep] = useState(0);
  // amount: form value (number)
  const [amount, setAmount] = useState(null);

  // session state — all written only after init succeeds.
  const [session, setSession] = useState(null); // { session_id, R[], N, amount, expires_at }
  const [jIndex, setJIndex] = useState(null);     // picked j after submit
  const [token, setToken] = useState(null);       // final unblinded token { serial, amount, R_prime, s_prime }

  // UI flags
  const [loading, setLoading] = useState(false);
  const [loadingLabel, setLoadingLabel] = useState('');
  const [error, setError] = useState(null);
  const [now, setNow] = useState(() => Date.now()); // for TTL countdown ticking

  // ── 🔴 CRITICAL: blinders live in a ref, NOT state ──
  // They must NEVER reach sessionStorage / localStorage / any persist layer.
  // useRef + immediate discard after unblind keeps them inside main-thread
  // memory only; a page refresh wipes them (intentional — refresh = abort).
  const blindersRef = useRef([]);   // [{ alpha: bigint, beta: bigint }, ...N]
  const candidatesRef = useRef([]); // [{ e, R_prime, serial }, ...N] — submit payload
  const sessionActiveRef = useRef(false); // for beforeunload guard

  // ── beforeunload: warn if a session is in progress (step 1..3) ──
  useEffect(() => {
    const handler = (e) => {
      if (!sessionActiveRef.current) return;
      // Standard cross-browser "are you sure?" trigger.
      e.preventDefault();
      e.returnValue = ''; // Chrome requires this to pop the confirmation.
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, []);

  // ── TTL countdown ticker (1 Hz) ──
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  // TTL display
  const ttlMs = session ? Math.max(0, new Date(session.expires_at).getTime() - now) : 0;
  const ttlExpired = session && ttlMs <= 0;

  // ────────────────────────────────────────────────────────────────────
  // ① init: POST /api/withdraw/init { amount }
  // ────────────────────────────────────────────────────────────────────
  const handleInit = useCallback(async () => {
    setLoading(true);
    setLoadingLabel('正在发起取款会话…');
    setError(null);
    try {
      // Front-side guard: amount must be a positive int ≤ balance.
      if (!Number.isInteger(amount) || amount <= 0) {
        throw Object.assign(new Error('amount'), { response: { data: { error: 'INVALID_AMOUNT' } } });
      }
      if (amount > (user?.balance ?? 0)) {
        throw Object.assign(new Error('balance'), { response: { data: { error: 'INSUFFICIENT_BALANCE' } } });
      }
      // Fetch bank public key (unauthenticated).
      const pubRes = await api.get('/bank/pubkey');
      const publicKeyHex = pubRes.data.public_key;
      const publicKey = hexToBytes(publicKeyHex);

      // Call init.
      const { data } = await api.post('/withdraw/init', { amount });
      // data = { session_id, R: ["hex66"...], amount, N }
      const expires_at = new Date(Date.now() + SESSION_TTL_MS).toISOString();
      const newSession = {
        session_id: data.session_id,
        R: data.R,
        N: data.N,
        amount: data.amount,
        publicKeyHex,
        publicKey,
        expires_at,
      };
      setSession(newSession);
      sessionActiveRef.current = true;

      // Optimistic local balance sync (backend already debited).
      // We DO NOT await a fresh user fetch — /auth/me doesn't exist, and the
      // optimistic decrement is correct unless another tab mutated the same
      // user (a non-goal of the demo).
      updateUser({ balance: (user?.balance ?? 0) - amount });

      message.success('会话已建立，进入下一步');
      setStep(1);
    } catch (e) {
      setError(mapApiError(e, 'init 失败'));
    } finally {
      setLoading(false);
      setLoadingLabel('');
    }
  }, [amount, user, updateUser]);

  // ────────────────────────────────────────────────────────────────────
  // ② clientBuildCandidates + submit
  //    Pure-local computation first (N candidates), then one POST.
  // ────────────────────────────────────────────────────────────────────
  const handleSubmit = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    setLoadingLabel(`正在本地构造 ${session.N} 个盲化候选…`);
    setError(null);
    try {
      // Local: build N candidates. blinders stay in the ref only.
      const candidates = [];
      const blinders = [];
      for (let i = 0; i < session.N; i++) {
        const R = hexToBytes(session.R[i]);
        const bl = generateBlinders(); // { alpha, beta }
        const RPrime = computeBlindedCommitment(R, bl.alpha, bl.beta, session.publicKey);
        const serial = new Uint8Array(32);
        globalThis.crypto.getRandomValues(serial);
        const ePrime = hashToScalar(TOKEN_DOMAIN_TAG, RPrime, serial, session.amount, session.publicKey);
        const e = modN(ePrime + bl.beta);
        candidates.push({
          e: scalarToHexFixed(e),
          R_prime: bytesToHex(RPrime),
          serial: bytesToHex(serial),
        });
        blinders.push({ alpha: bl.alpha, beta: bl.beta });
      }
      blindersRef.current = blinders;
      candidatesRef.current = candidates;

      setLoadingLabel('正在提交候选至银行…');
      const { data } = await api.post('/withdraw/submit', {
        session_id: session.session_id,
        candidates,
      });
      // data = { j }
      setJIndex(data.j);
      message.success(`银行选中候选 j=${data.j}，进入下一步`);
      setStep(2);
    } catch (e) {
      setError(mapApiError(e, 'submit 失败'));
    } finally {
      setLoading(false);
      setLoadingLabel('');
    }
  }, [session]);

  // ────────────────────────────────────────────────────────────────────
  // ③ reveal + unblind
  // ────────────────────────────────────────────────────────────────────
  const handleReveal = useCallback(async () => {
    if (!session || jIndex === null) return;
    setLoading(true);
    setLoadingLabel('正在揭示 α/β (i≠j) 并等待银行签名…');
    setError(null);
    try {
      const revealed = [];
      for (let i = 0; i < session.N; i++) {
        if (i === jIndex) continue;
        revealed.push({
          i,
          alpha: scalarToHexFixed(blindersRef.current[i].alpha),
          beta: scalarToHexFixed(blindersRef.current[i].beta),
        });
      }
      const { data } = await api.post('/withdraw/reveal', {
        session_id: session.session_id,
        revealed,
      });
      // data = { s_j: "hex64" }
      const sJ = hexToScalarFixed(data.s_j);
      const alphaJ = blindersRef.current[jIndex].alpha;
      const sPrime = unblindResponse(sJ, alphaJ); // bigint

      const candJ = candidatesRef.current[jIndex];
      const finalToken = {
        serial: candJ.serial,
        amount: session.amount,
        R_prime: candJ.R_prime,
        s_prime: scalarToHexFixed(sPrime),
      };
      setToken(finalToken);

      // α/β have served their purpose — drop them so they can't leak later.
      blindersRef.current = [];
      candidatesRef.current = [];

      message.success('取款完成！token 已生成。');
      setStep(3);
    } catch (e) {
      setError(mapApiError(e, 'reveal 失败'));
    } finally {
      setLoading(false);
      setLoadingLabel('');
    }
  }, [session, jIndex]);

  // ────────────────────────────────────────────────────────────────────
  // helpers
  // ────────────────────────────────────────────────────────────────────
  const resetSession = useCallback(() => {
    setSession(null);
    setJIndex(null);
    setToken(null);
    setStep(0);
    setAmount(null);
    blindersRef.current = [];
    candidatesRef.current = [];
    sessionActiveRef.current = false;
    setError(null);
  }, []);

  // ────────────────────────────────────────────────────────────────────
  // ⑦ cancel: POST /api/withdraw/cancel → refund + reset to step 0
  // ────────────────────────────────────────────────────────────────────
  const handleCancel = useCallback(async () => {
    if (!session) {
      // No session in front-end state — nothing to cancel locally.
      setStep(0);
      return;
    }
    setLoading(true);
    setLoadingLabel('正在取消取款并退还余额…');
    setError(null);
    try {
      const { data } = await api.post('/withdraw/cancel', {
        session_id: session.session_id,
      });
      // data = { refunded, new_balance }
      updateUser({ balance: data.new_balance });
      message.success(`已取消取款，余额已退还 (+${data.refunded})`);
      resetSession();
    } catch (e) {
      setError(mapApiError(e, 'cancel 失败'));
    } finally {
      setLoading(false);
      setLoadingLabel('');
    }
  }, [session, updateUser, resetSession]);

  async function copyToken() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(token));
      message.success('Token 已复制到剪贴板');
    } catch {
      message.error('复制失败，请手动选择文本复制');
    }
  }

  // ────────────────────────────────────────────────────────────────────
  // render
  // ────────────────────────────────────────────────────────────────────
  const stepItems = [
    { title: '① 发起', description: '输入金额并初始化会话' },
    { title: '② 提交', description: '本地构造 N 候选并提交' },
    { title: '③ 揭示', description: '揭示 α/β (i≠j) 拿 s_j' },
    { title: '④ 完成', description: 'unblind → token 展示' },
  ];

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Card>
        <Title level={3} style={{ marginTop: 0 }}>取款向导</Title>
        <Alert
          message="盲化因子 α/β 仅存于本页内存"
          description="刷新 / 关闭页面将丢失 α/β，本次取款会作废。如需中止，请点击下方「取消取款」按钮（会退还余额至账户）。"
          type="warning"
          showIcon
          icon={<ExclamationCircleOutlined />}
          action={
            session && step < 3 ? (
              <Button size="small" danger onClick={handleCancel} loading={loading}>
                取消取款
              </Button>
            ) : null
          }
        />
        <Steps
          current={step}
          size="small"
          items={stepItems}
          style={{ marginTop: 16 }}
        />
      </Card>

      {/* TTL countdown + active-session banner */}
      {session && step < 3 && (
        <Card size="small">
          <Row gutter={16} align="middle">
            <Col flex="auto">
              <Statistic
                title="会话剩余时间"
                value={ttlExpired ? '已过期' : fmtCountdown(ttlMs)}
                valueStyle={ttlExpired ? { color: '#cf1322' } : (ttlMs < 60_000 ? { color: '#fa8c16' } : undefined)}
              />
            </Col>
            <Col>
              <Descriptions size="small" column={1}>
                <Descriptions.Item label="会话 ID">
                  <Text code copyable style={{ fontSize: 12 }}>{session.session_id}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="N (候选数)">
                  <Tag color="blue">{session.N}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label="取款金额">
                  <Text strong>{session.amount}</Text>
                </Descriptions.Item>
              </Descriptions>
            </Col>
          </Row>
          {ttlExpired && (
            <Alert
              style={{ marginTop: 12 }}
              type="error"
              showIcon
              message="会话已过期"
              description="服务器已自动退还余额。请点击「取消取款」清理本地状态，然后重新开始。"
            />
          )}
        </Card>
      )}

      {/* Step 0: 输入金额 */}
      {step === 0 && (
        <Card title="① 发起取款会话">
          {error && <Alert message={error} type="error" showIcon closable onClose={() => setError(null)} style={{ marginBottom: 16 }} />}
          <Form layout="vertical" autoComplete="off">
            <Form.Item
              label="取款金额"
              extra={`当前余额：${user?.balance ?? 0}（顾客初始 100）`}
              rules={[
                { required: true, message: '请输入取款金额' },
                {
                  validator: (_, v) => {
                    if (v == null) return Promise.resolve();
                    if (!Number.isInteger(v)) return Promise.reject(new Error('金额必须为正整数'));
                    if (v <= 0) return Promise.reject(new Error('金额必须大于 0'));
                    if (v > (user?.balance ?? 0)) return Promise.reject(new Error('金额不能超过当前余额'));
                    return Promise.resolve();
                  },
                },
              ]}
            >
              <InputNumber
                style={{ width: 200 }}
                min={1}
                step={1}
                precision={0}
                placeholder="如 30"
                value={amount}
                onChange={(v) => setAmount(v)}
              />
            </Form.Item>
            <Form.Item>
              <Button
                type="primary"
                onClick={handleInit}
                loading={loading}
                disabled={amount == null}
              >
                {loading ? loadingLabel : '发起取款'}
              </Button>
            </Form.Item>
          </Form>
        </Card>
      )}

      {/* Step 1: client build + submit */}
      {step === 1 && (
        <Card title="② 本地构造候选并提交">
          {error && <Alert message={error} type="error" showIcon closable onClose={() => setError(null)} style={{ marginBottom: 16 }} />}
          <Paragraph>
            客户端将本地生成 <Text code>{session.N}</Text> 个盲化候选 (α_i, β_i 仅存内存)，
            计算每个 <Text code>R'_i = R_i + α_i·G + β_i·P</Text> 与盲化挑战 <Text code>e_i = (e'_i + β_i) mod n</Text>，
            然后把 <Text code>{'{ e, R_prime, serial }'}</Text> 数组提交给银行。
            <br />
            <Text type="secondary">注意：α/β 永不出本机，提交 payload 仅含 { '{e, R_prime, serial}' }。</Text>
          </Paragraph>
          <Spin spinning={loading} tip={loadingLabel}>
            <Button type="primary" onClick={handleSubmit} loading={loading} disabled={ttlExpired}>
              构造并提交候选
            </Button>
          </Spin>
        </Card>
      )}

      {/* Step 2: reveal + unblind */}
      {step === 2 && (
        <Card title="③ 揭示 α/β (i≠j) 并解盲">
          {error && <Alert message={error} type="error" showIcon closable onClose={() => setError(null)} style={{ marginBottom: 16 }} />}
          <Paragraph>
            银行选中候选 <Tag color="orange">j = {jIndex}</Tag>。
            客户端将对其余 <Text code>N-1 = {session.N - 1}</Text> 个候选揭示 <Text code>(α_i, β_i)</Text>，
            供银行做 cut-and-choose 校验。校验通过后银行返回 <Text code>s_j</Text>，
            客户端本地计算 <Text code>s' = (s_j + α_j) mod n</Text> 完成解盲。
          </Paragraph>
          <Spin spinning={loading} tip={loadingLabel}>
            <Button type="primary" onClick={handleReveal} loading={loading} disabled={ttlExpired}>
              揭示并解盲
            </Button>
          </Spin>
        </Card>
      )}

      {/* Step 3: token 展示 */}
      {step === 3 && token && (
        <Card title="④ 取款完成 — Token 已生成">
          <Alert
            type="success"
            showIcon
            message="盲签名 token 已生成"
            description="请复制下方 token，到「商户支付页」粘贴以完成存款（M6 step 2 将实现）。"
          />
          <Descriptions column={1} bordered size="small" style={{ marginTop: 16 }}>
            <Descriptions.Item label="serial (32B)"><Text code copyable style={{ fontSize: 12 }}>{token.serial}</Text></Descriptions.Item>
            <Descriptions.Item label="amount"><Text strong>{token.amount}</Text></Descriptions.Item>
            <Descriptions.Item label="R_prime (33B)"><Text code copyable style={{ fontSize: 12 }}>{token.R_prime}</Text></Descriptions.Item>
            <Descriptions.Item label="s_prime (32B)"><Text code copyable style={{ fontSize: 12 }}>{token.s_prime}</Text></Descriptions.Item>
          </Descriptions>
          <Space style={{ marginTop: 16 }}>
            <Button type="primary" icon={<CopyOutlined />} onClick={copyToken}>复制完整 Token JSON</Button>
            <Button onClick={() => navigate('/dashboard')}>返回仪表盘</Button>
          </Space>
          <Paragraph type="secondary" style={{ marginTop: 12, fontSize: 12 }}>
            该 token 任何人持有即可向商户存款（盲签名不可追踪）。请妥善保管。
          </Paragraph>
          <Input.TextArea
            value={JSON.stringify(token, null, 2)}
            autoSize={{ minRows: 6, maxRows: 10 }}
            readOnly
            style={{ marginTop: 8, fontFamily: 'monospace', fontSize: 12 }}
          />
        </Card>
      )}

      {/* 全局 cancel/error 区域（step 1..3 都需要看到 cancel 按钮） */}
      {session && step >= 1 && step < 3 && (
        <Card size="small">
          <Space>
            <Button danger onClick={handleCancel} loading={loading} disabled={ttlExpired}>
              取消取款（退还余额）
            </Button>
            {ttlExpired && (
              <Button onClick={handleCancel}>清理过期会话</Button>
            )}
          </Space>
        </Card>
      )}

      {error && step >= 1 && (
        <Result
          status="warning"
          title="出现错误"
          subTitle={error}
          extra={
            <Button type="primary" onClick={() => setError(null)}>
              知道了
            </Button>
          }
        />
      )}
    </Space>
  );
}
