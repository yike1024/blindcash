// pages/Withdraw.jsx — customer 4-move 取款向导 (vault restyle)
//
// ALL CRYPTO LOGIC, REFS, BEFOREUNLOAD, TTL COUNTDOWN PRESERVED VERBATIM.
// Only the presentation layer (JSX structure, classNames, inline theme) is
// restyled to the Cryptographic Vault design system.
//
//   🔴 α/β only live in memory (useRef) — refresh/closes page → 取款作废.
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

import { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Steps, Form, InputNumber, Button, Alert, Space, Typography,
  Descriptions, message, Result, Spin, Input,
} from 'antd';
import { CopyOutlined, LockOutlined, WalletOutlined } from '@ant-design/icons';

import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';
import { putCoin } from '../utils/walletDB.js';
import { generateBlinders, computeBlindedCommitment, unblindResponse } from '@crypto/client/blinding.js';
import { hashToScalar } from '@crypto/server/hashToScalar.js';
import { modN } from '@crypto/server/curve.js';
import { bytesToHex, hexToBytes } from '@utils/hex.js';
import { TOKEN_DOMAIN_TAG } from '@crypto/client/protocolConstants.js';

const { Text, Paragraph } = Typography;

// ── helpers ────────────────────────────────────────────────────────────
function scalarToHexFixed(s) {
  let h = s.toString(16);
  while (h.length < 64) h = '0' + h;
  if (h.length > 64) h = h.slice(h.length - 64);
  return h;
}
function hexToScalarFixed(hex) {
  let v = 0n;
  for (let i = 0; i < hex.length; i++) {
    v = (v << 4n) | BigInt(parseInt(hex[i], 16));
  }
  return v;
}

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

  const [step, setStep] = useState(0);
  const [amount, setAmount] = useState(null);

  const [session, setSession] = useState(null);
  const [jIndex, setJIndex] = useState(null);
  const [token, setToken] = useState(null);
  // Phase 2: 是否已存入钱包（防止重复存入）
  const [savedToWallet, setSavedToWallet] = useState(false);

  const [loading, setLoading] = useState(false);
  const [loadingLabel, setLoadingLabel] = useState('');
  const [error, setError] = useState(null);
  const [now, setNow] = useState(() => Date.now());

  // ── 🔴 CRITICAL: blinders live in a ref, NOT state ──
  const blindersRef = useRef([]);
  const candidatesRef = useRef([]);
  const sessionActiveRef = useRef(false);

  useEffect(() => {
    const handler = (e) => {
      if (!sessionActiveRef.current) return;
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, []);

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const ttlMs = session ? Math.max(0, new Date(session.expires_at).getTime() - now) : 0;
  const ttlExpired = session && ttlMs <= 0;
  const ttlWarn = ttlMs > 0 && ttlMs < 60_000;

  // ────────────────────────────────────────────────────────────────────
  // ① init
  // ────────────────────────────────────────────────────────────────────
  const handleInit = useCallback(async () => {
    setLoading(true);
    setLoadingLabel('正在发起取款会话…');
    setError(null);
    try {
      if (!Number.isInteger(amount) || amount <= 0) {
        throw Object.assign(new Error('amount'), { response: { data: { error: 'INVALID_AMOUNT' } } });
      }
      if (amount > (user?.balance ?? 0)) {
        throw Object.assign(new Error('balance'), { response: { data: { error: 'INSUFFICIENT_BALANCE' } } });
      }
      const pubRes = await api.get('/bank/pubkey');
      const publicKeyHex = pubRes.data.public_key;
      const publicKey = hexToBytes(publicKeyHex);

      const { data } = await api.post('/withdraw/init', { amount });
      const expires_at = new Date(Date.now() + data.ttl_ms).toISOString();
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
  // ────────────────────────────────────────────────────────────────────
  const handleSubmit = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    setLoadingLabel(`正在本地构造 ${session.N} 个盲化候选…`);
    setError(null);
    try {
      const candidates = [];
      const blinders = [];
      for (let i = 0; i < session.N; i++) {
        const R = hexToBytes(session.R[i]);
        const bl = generateBlinders();
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
      const sJ = hexToScalarFixed(data.s_j);
      const alphaJ = blindersRef.current[jIndex].alpha;
      const sPrime = unblindResponse(sJ, alphaJ);

      const candJ = candidatesRef.current[jIndex];
      const finalToken = {
        // Phase 1 (v5 §三 1.7 token v2 schema)：含 v:2 与 key_id 字段。
        // key_id 来自 reveal 步骤后端返回（revealAndSign 返回
        // {s_j, key_id:1}）；缺省时 fallback 到 1（Phase 1 单密钥）。
        // 支付/退币时把 key_id 透传给 processPayment，由它走
        // getPublicKeyByVersion(key_id) 验签——Phase 3 多密钥轮换铺路。
        v: 2,
        key_id: data.key_id ?? 1,
        serial: candJ.serial,
        amount: session.amount,
        R_prime: candJ.R_prime,
        s_prime: scalarToHexFixed(sPrime),
      };
      setToken(finalToken);

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

  const resetSession = useCallback(() => {
    setSession(null);
    setJIndex(null);
    setToken(null);
    setSavedToWallet(false);
    setStep(0);
    setAmount(null);
    blindersRef.current = [];
    candidatesRef.current = [];
    sessionActiveRef.current = false;
    setError(null);
  }, []);

  const handleCancel = useCallback(async () => {
    if (!session) {
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

  // Phase 2 §2.2: 存入客户端 IndexedDB 钱包。
  // 此操作不调用任何后端 API——银行无感知（方案 A 钱包在客户端，
  // 否则银行可关联 serial → 用户身份，摧毁匿名性）。
  async function handleSaveToWallet() {
    if (!token) return;
    try {
      await putCoin(token);
      setSavedToWallet(true);
      message.success('Token 已存入钱包（IndexedDB）');
    } catch (e) {
      // ConstraintError = 同 serial 已在钱包中（重复存入无意义）
      if (e?.name === 'ConstraintError' || e?.message?.includes('already')) {
        setSavedToWallet(true);
        message.info('此 Token 已在钱包中');
      } else {
        message.error(`存入钱包失败：${e.message}`);
      }
    }
  }

  // ────────────────────────────────────────────────────────────────────
  // render
  // ────────────────────────────────────────────────────────────────────
  const stepItems = [
    { title: '发起', description: '输入金额' },
    { title: '提交', description: '构造 N 候选' },
    { title: '揭示', description: '揭示 α/β' },
    { title: '完成', description: '解盲 → token' },
  ];

  return (
    <div className="bc-page" style={{ paddingTop: 32, paddingBottom: 64 }}>
      {/* ── Page header ── */}
      <header className="bc-rise-1" style={{ marginBottom: 28 }}>
        <p className="bc-eyebrow" style={{ marginBottom: 10 }}>顾客 · 取款向导</p>
        <h1 className="bc-display" style={{ fontSize: 'clamp(32px, 4vw, 44px)', margin: 0 }}>
          向银行申请盲签名 token
        </h1>
      </header>

      {/* ── Safety banner ── */}
      <Alert
        className="bc-rise-2"
        message={
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <LockOutlined style={{ color: 'var(--gold-400)' }} />
            盲化因子 α/β 仅存于本页内存
          </span>
        }
        description="刷新 / 关闭页面将丢失 α/β，本次取款会作废。如需中止，请点击下方「取消取款」按钮（会退还余额至账户）。"
        type="warning"
        showIcon={false}
        action={
          session && step < 3 ? (
            <Button size="small" danger onClick={handleCancel} loading={loading}>
              取消取款
            </Button>
          ) : null
        }
        style={{ marginBottom: 24 }}
      />

      {/* ── Steps ── */}
      <div className="bc-card bc-rise-2" style={{ padding: '20px 24px', marginBottom: 24 }}>
        <Steps current={step} size="small" items={stepItems} />
      </div>

      {/* ── TTL countdown + active-session banner ── */}
      {session && step < 3 && (
        <div className="bc-card bc-rise-3" style={{ padding: '20px 24px', marginBottom: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 24, flexWrap: 'wrap' }}>
            <div>
              <div className="bc-stat-label" style={{ marginBottom: 6 }}>会话剩余时间</div>
              <div
                className="bc-mono"
                style={{
                  fontSize: 30,
                  fontWeight: 500,
                  fontVariantNumeric: 'tabular-nums',
                  color: ttlExpired ? 'var(--crimson-400)' : ttlWarn ? 'var(--gold-400)' : 'var(--paper-100)',
                  letterSpacing: '0.02em',
                }}
              >
                {ttlExpired ? '已过期' : fmtCountdown(ttlMs)}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap' }}>
              <Meta label="会话 ID">
                <span className="bc-mono bc-scalar" style={{ fontSize: 11, maxWidth: 220 }}>
                  {session.session_id}
                </span>
              </Meta>
              <Meta label="候选数 N">
                <span className="bc-chip bc-chip--gold">{session.N}</span>
              </Meta>
              <Meta label="取款金额">
                <span className="bc-mono" style={{ fontSize: 20, color: 'var(--gold-400)' }}>{session.amount}</span>
              </Meta>
            </div>
          </div>
          {ttlExpired && (
            <Alert
              style={{ marginTop: 16 }}
              type="error"
              showIcon
              message="会话已过期"
              description="服务器已自动退还余额。请点击「取消取款」清理本地状态，然后重新开始。"
            />
          )}
        </div>
      )}

      {/* ── Step 0: 输入金额 ── */}
      {step === 0 && (
        <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
          <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>① 发起取款会话</h2>
          <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 20 }}>
            POST /api/withdraw/init
          </p>
          {error && <Alert message={error} type="error" showIcon closable onClose={() => setError(null)} style={{ marginBottom: 16 }} />}
          <Form layout="vertical" autoComplete="off" requiredMark={false}>
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
                style={{ width: 220 }}
                min={1}
                step={1}
                precision={0}
                placeholder="如 30"
                value={amount}
                onChange={(v) => setAmount(v)}
              />
            </Form.Item>
            <Form.Item>
              <Button type="primary" onClick={handleInit} loading={loading} disabled={amount == null}>
                {loading ? loadingLabel : '发起取款'}
              </Button>
            </Form.Item>
          </Form>
        </section>
      )}

      {/* ── Step 1: client build + submit ── */}
      {step === 1 && (
        <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
          <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>② 本地构造候选并提交</h2>
          <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 20 }}>
            client build · POST /api/withdraw/submit
          </p>
          {error && <Alert message={error} type="error" showIcon closable onClose={() => setError(null)} style={{ marginBottom: 16 }} />}
          <Paragraph style={{ color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.8 }}>
            客户端将本地生成 <span className="bc-mono" style={{ color: 'var(--gold-400)' }}>{session.N}</span> 个盲化候选 (α_i, β_i 仅存内存)，
            计算每个 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>R'_i = R_i + α_i·G + β_i·P</span> 与盲化挑战 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>e_i = (e'_i + β_i) mod n</span>，
            然后把 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>&#123; e, R_prime, serial &#125;</span> 数组提交给银行。
            <br />
            <span style={{ color: 'var(--text-muted)', fontSize: 12.5 }}>注意：α/β 永不出本机，提交 payload 仅含 &#123;e, R_prime, serial&#125;。</span>
          </Paragraph>
          <Spin spinning={loading} tip={loadingLabel}>
            <Button type="primary" onClick={handleSubmit} loading={loading} disabled={ttlExpired}>
              构造并提交候选
            </Button>
          </Spin>
        </section>
      )}

      {/* ── Step 2: reveal + unblind ── */}
      {step === 2 && (
        <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
          <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>③ 揭示 α/β (i≠j) 并解盲</h2>
          <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 20 }}>
            POST /api/withdraw/reveal · unblind
          </p>
          {error && <Alert message={error} type="error" showIcon closable onClose={() => setError(null)} style={{ marginBottom: 16 }} />}
          <Paragraph style={{ color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.8 }}>
            银行选中候选 <span className="bc-chip bc-chip--gold">j = {jIndex}</span>。
            客户端将对其余 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>N-1 = {session.N - 1}</span> 个候选揭示 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>(α_i, β_i)</span>，
            供银行做 cut-and-choose 校验。校验通过后银行返回 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>s_j</span>，
            客户端本地计算 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>s' = (s_j + α_j) mod n</span> 完成解盲。
          </Paragraph>
          <Spin spinning={loading} tip={loadingLabel}>
            <Button type="primary" onClick={handleReveal} loading={loading} disabled={ttlExpired}>
              揭示并解盲
            </Button>
          </Spin>
        </section>
      )}

      {/* ── Step 3: token 展示 ── */}
      {step === 3 && token && (
        <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
          <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>④ 取款完成 — Token 已生成</h2>
          <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 20 }}>
            unblinded signature · ready to spend
          </p>
          <Alert
            type="success"
            showIcon
            message="盲签名 token 已生成"
            description="请复制下方 token，交付商户以完成存款。任何持有银行公钥者均可验真，但无人能追溯其来源。"
            style={{ marginBottom: 20 }}
          />
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="serial (32B)"><Text code copyable style={{ fontSize: 12 }}>{token.serial}</Text></Descriptions.Item>
            <Descriptions.Item label="amount"><Text strong>{token.amount}</Text></Descriptions.Item>
            <Descriptions.Item label="R_prime (33B)"><Text code copyable style={{ fontSize: 12 }}>{token.R_prime}</Text></Descriptions.Item>
            <Descriptions.Item label="s_prime (32B)"><Text code copyable style={{ fontSize: 12 }}>{token.s_prime}</Text></Descriptions.Item>
          </Descriptions>
          <Space style={{ marginTop: 20 }}>
            <Button type="primary" icon={<CopyOutlined />} onClick={copyToken}>复制完整 Token JSON</Button>
            <Button
              icon={<WalletOutlined />}
              onClick={handleSaveToWallet}
              disabled={savedToWallet}
            >
              {savedToWallet ? '✓ 已存入钱包' : '存入钱包'}
            </Button>
            <Button onClick={() => navigate('/dashboard')}>返回仪表盘</Button>
          </Space>
          <Paragraph type="secondary" style={{ marginTop: 14, fontSize: 12, color: 'var(--text-muted)' }}>
            该 token 任何人持有即可向商户存款（盲签名不可追踪）。请妥善保管。
          </Paragraph>
          <Input.TextArea
            value={JSON.stringify(token, null, 2)}
            autoSize={{ minRows: 6, maxRows: 10 }}
            readOnly
            style={{ marginTop: 8, fontFamily: 'var(--font-mono)', fontSize: 12 }}
          />
        </section>
      )}

      {/* ── Global cancel/error region ── */}
      {session && step >= 1 && step < 3 && (
        <section className="bc-card" style={{ padding: '16px 24px', marginBottom: 24 }}>
          <Space>
            <Button danger onClick={handleCancel} loading={loading} disabled={ttlExpired}>
              取消取款（退还余额）
            </Button>
            {ttlExpired && (
              <Button onClick={handleCancel}>清理过期会话</Button>
            )}
          </Space>
        </section>
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
    </div>
  );
}

function Meta({ label, children }) {
  return (
    <div>
      <div className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 6 }}>
        {label}
      </div>
      {children}
    </div>
  );
}
