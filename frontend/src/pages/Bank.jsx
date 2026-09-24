// pages/Bank.jsx — Phase 1: 银行充值/退币双 tab
//
// v5 §三 1.2 + 1.3 + 1.6:
//   充值 tab  — 自助充值（simulated fiat rail），POST /api/bank/deposit
//               单次上限 1000 BC，24h 滚动累计上限 5000 BC
//   退币 tab  — 粘贴自己取款得到的 token，本地预验签后 POST /api/bank/redeem
//               redeem = processPayment({merchant_id: 自己, ...token})，
//               与商户收款共享 spent_coins 表（同一 token 只能兑付一次）
//
// Phase 1 (v5 §三 1.5 开户改革)：新用户 balance=0，必须先充值才能取款。
// Dashboard 在余额=0 时主 CTA 指向本页。

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Tabs, Input, InputNumber, Button, Space, Typography, Descriptions, Alert,
  message, Result, Spin, Tag,
} from 'antd';
import {
  CheckCircleTwoTone, CloseCircleTwoTone, BankOutlined, ArrowRightOutlined,
} from '@ant-design/icons';

import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';
import { verifySig } from '@crypto/client/schnorrBlindClient.js';
import { isValidCompressedFormat } from '@crypto/client/pointFormat.js';
import { hexToBytes } from '@utils/hex.js';
import CollapsibleHint from '../components/CollapsibleHint.jsx';

const { Text, Paragraph } = Typography;
const { TextArea } = Input;

const HEX64_RE = /^[0-9a-fA-F]{64}$/;
const MAX_DEPOSIT_PER_TX = 1000;
const MAX_DEPOSIT_PER_DAY = 5000;

// ── token format check (shared logic with Payment.jsx, token v2 aware) ──
function cheapFormatCheck(tok) {
  if (typeof tok.serial !== 'string' || !HEX64_RE.test(tok.serial)) {
    return { ok: false, reason: 'serial 必须是 64 位 hex 字符串' };
  }
  if (!Number.isInteger(tok.amount) || tok.amount <= 0) {
    return { ok: false, reason: 'amount 必须为正整数' };
  }
  if (typeof tok.R_prime !== 'string' || !isValidCompressedFormat(tok.R_prime)) {
    return { ok: false, reason: "R_prime 必须是 33 字节压缩格式 (66 hex, 前缀 02/03)" };
  }
  if (typeof tok.s_prime !== 'string' || !HEX64_RE.test(tok.s_prime)) {
    return { ok: false, reason: 's_prime 必须是 64 位 hex 字符串' };
  }
  // Phase 1 token v2: 透传 key_id（如有）
  const fields = {
    serial: tok.serial,
    amount: tok.amount,
    R_prime: tok.R_prime,
    s_prime: tok.s_prime,
  };
  if (tok.key_id !== undefined) {
    fields.key_id = tok.key_id;
  }
  return { ok: true, fields };
}

function mapApiError(err, fallback = '操作失败') {
  const code = err?.response?.data?.error;
  const srvMsg = err?.response?.data?.message;
  switch (code) {
    case 'MALFORMED_TOKEN':
      return `token 字段格式错误：${srvMsg ?? ''}`;
    case 'SIGNATURE_INVALID':
      return '签名验证失败：token 被篡改或解盲错误。';
    case 'DOUBLE_SPEND':
      return '双花检测：此 token 已被花费过。';
    case 'VALIDATION_ERROR':
      return `请求参数缺失：${srvMsg ?? ''}`;
    case 'DEPOSIT_LIMIT_EXCEEDED':
      return `单次充值超限：${srvMsg ?? ''}`;
    case 'DAILY_LIMIT_EXCEEDED':
      return `日累计充值超限：${srvMsg ?? ''}`;
    case 'INSUFFICIENT_BALANCE':
      return '余额不足。';
    default:
      return fallback;
  }
}

export default function BankPage() {
  const { user, updateUser } = useAuth();
  const [activeTab, setActiveTab] = useState('deposit');

  return (
    <div className="bc-page" style={{ paddingTop: 32, paddingBottom: 64 }}>
      {/* ── Page header ── */}
      <header className="bc-rise-1" style={{ marginBottom: 28 }}>
        <p className="bc-eyebrow" style={{ marginBottom: 10 }}>
          <BankOutlined style={{ marginRight: 6 }} />银行
        </p>
        <h1 className="bc-display" style={{ fontSize: 'clamp(32px, 4vw, 44px)', margin: 0 }}>
          充值与退币
        </h1>
      </header>

      {/* ── Balance strip ── */}
      <section className="bc-card bc-rise-2" style={{ padding: '24px 28px', marginBottom: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 24, flexWrap: 'wrap' }}>
        <div>
          <div className="bc-stat-label" style={{ marginBottom: 8 }}>当前余额</div>
          <div className="bc-num" style={{ fontSize: 'clamp(34px, 4vw, 44px)', color: 'var(--gold-400)' }}>
            {user?.balance ?? 0}
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--text-muted)', marginLeft: 8, letterSpacing: '0.1em' }}>BC</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
          <Meta label="角色">
            <span className="bc-chip bc-chip--gold">{user?.role === 'merchant' ? '商户' : '顾客'}</span>
          </Meta>
          <Meta label="用户名">
            <span className="bc-mono" style={{ fontSize: 14, color: 'var(--paper-100)' }}>@{user?.username}</span>
          </Meta>
        </div>
      </section>

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'deposit',
            label: '充值',
            children: <DepositTab user={user} updateUser={updateUser} />,
          },
          {
            key: 'redeem',
            label: '退币',
            children: <RedeemTab user={user} updateUser={updateUser} />,
          },
        ]}
      />
    </div>
  );
}

// ── 充值 Tab ──
function DepositTab({ updateUser }) {
  const [amount, setAmount] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);

  const handleSubmit = useCallback(async () => {
    if (!Number.isInteger(amount) || amount <= 0) {
      message.warning('请输入正整数金额');
      return;
    }
    if (amount > MAX_DEPOSIT_PER_TX) {
      message.warning(`单次充值上限 ${MAX_DEPOSIT_PER_TX} BC`);
      return;
    }
    setSubmitting(true);
    setResult(null);
    try {
      const { data } = await api.post('/bank/deposit', { amount });
      updateUser({ balance: data.new_balance });
      setResult({
        kind: 'success',
        msg: `已充值 ${data.deposited} BC`,
        deposited: data.deposited,
        new_balance: data.new_balance,
      });
      message.success(`充值成功：+${data.deposited} BC`);
    } catch (e) {
      setResult({ kind: 'error', msg: mapApiError(e, '充值失败') });
    } finally {
      setSubmitting(false);
    }
  }, [amount, updateUser]);

  return (
    <div style={{ paddingTop: 8 }}>
      <div className="bc-rise-2">
        <CollapsibleHint title="模拟法币入账（simulated fiat rail）" tone="gold">
          <Space direction="vertical" size="small">
            <Text>
              自助充值模拟外部法币存入。单次上限
              <Tag color="gold" style={{ marginLeft: 6 }}>{MAX_DEPOSIT_PER_TX} BC</Tag>
              ，24 小时滚动累计上限
              <Tag color="gold" style={{ marginLeft: 6 }}>{MAX_DEPOSIT_PER_DAY} BC</Tag>
              。
            </Text>
            <Text type="secondary" style={{ fontSize: 12 }}>
              充值后 reserve_balance 与 SUM(users.balance) 同步增加，assertInvariant 自动校验。
            </Text>
          </Space>
        </CollapsibleHint>
      </div>

      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>输入充值金额</h2>
        <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 18 }}>
          simulated fiat rail · 1-1000 bc per tx
        </p>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <InputNumber
            value={amount}
            onChange={setAmount}
            min={1}
            max={MAX_DEPOSIT_PER_TX}
            step={10}
            precision={0}
            parser={(v) => v.replace(/[^\d]/g, '')}
            style={{ width: '100%', fontSize: 20, fontFamily: 'var(--font-mono)' }}
            placeholder="输入充值金额（BC）"
            size="large"
          />
          <Button
            type="primary"
            size="large"
            icon={<ArrowRightOutlined />}
            onClick={handleSubmit}
            loading={submitting}
            disabled={!Number.isInteger(amount) || amount <= 0}
          >
            确认充值
          </Button>
        </Space>
      </section>

      {result && (
        <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
          {result.kind === 'success' ? (
            <Result
              status="success"
              title={`+${result.deposited} BC 已入账`}
              subTitle={`新余额：${result.new_balance} BC`}
            />
          ) : (
            <Result
              status="error"
              title="充值失败"
              subTitle={result.msg}
            />
          )}
        </section>
      )}
    </div>
  );
}

// ── 退币 Tab ──
function RedeemTab({ updateUser }) {
  const [rawText, setRawText] = useState('');
  const [preview, setPreview] = useState({ phase: 'empty' });
  const publicKeyRef = useRef(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);

  // Load bank public key for local pre-verify
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await api.get('/bank/pubkey');
        if (cancelled) return;
        publicKeyRef.current = hexToBytes(data.public_key);
      } catch {
        if (!cancelled) {
          message.error('无法获取银行公钥，请刷新页面重试');
        }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // Debounced local pre-verify (same logic as Payment.jsx)
  useEffect(() => {
    setResult(null);
    const text = rawText.trim();
    if (!text) {
      setPreview({ phase: 'empty' });
      return;
    }

    setPreview({ phase: 'parsing' });
    const timer = setTimeout(async () => {
      let tok;
      try {
        tok = JSON.parse(text);
      } catch (e) {
        setPreview({ phase: 'invalid', reason: `JSON 解析失败：${e.message}` });
        return;
      }
      if (!tok || typeof tok !== 'object') {
        setPreview({ phase: 'invalid', reason: 'token 必须是 JSON 对象' });
        return;
      }
      const fmt = cheapFormatCheck(tok);
      if (!fmt.ok) {
        setPreview({ phase: 'invalid', reason: fmt.reason });
        return;
      }
      if (!publicKeyRef.current) {
        setPreview({ phase: 'invalid', reason: '银行公钥尚未加载，请稍候再试' });
        return;
      }
      try {
        const RPrime = hexToBytes(fmt.fields.R_prime);
        const sPrime = hexToBytes(fmt.fields.s_prime);
        const ok = verifySig(
          RPrime,
          sPrime,
          hexToBytes(fmt.fields.serial),
          fmt.fields.amount,
          publicKeyRef.current,
        );
        setPreview({
          phase: 'ok',
          token: fmt.fields,
          verifyOk: ok,
          reason: ok
            ? "本地预验签通过 (s'·G == R' + e'·P)"
            : '本地预验签失败：签名无效或字段被篡改',
        });
      } catch (e) {
        setPreview({ phase: 'invalid', reason: `本地曲线运算异常：${e.message}` });
      }
    }, 300);

    return () => clearTimeout(timer);
  }, [rawText]);

  const handleSubmit = useCallback(async () => {
    if (preview.phase !== 'ok' || !preview.verifyOk) {
      message.warning('请先粘贴并通过本地预验签');
      return;
    }
    setSubmitting(true);
    setResult(null);
    try {
      const { data } = await api.post('/bank/redeem', preview.token);
      updateUser({ balance: data.new_balance });
      setResult({
        kind: 'success',
        msg: `已退币 ${data.deposited} BC`,
        deposited: data.deposited,
        new_balance: data.new_balance,
      });
      message.success(`退币成功：+${data.deposited} BC`);
    } catch (e) {
      setResult({ kind: 'error', msg: mapApiError(e, '退币失败') });
    } finally {
      setSubmitting(false);
    }
  }, [preview, updateUser]);

  const previewBadge = (() => {
    if (preview.phase === 'empty') {
      return (
        <Alert
          type="info"
          showIcon
          message="将 token JSON 粘贴到下方文本框"
          description="退币 = 把自己取款得到的 token 兑付到自己账户。与商户收款共享 spent_coins 表（同一 token 只能兑付一次）。"
        />
      );
    }
    if (preview.phase === 'parsing') {
      return <Spin tip="正在解析并预验签…" />;
    }
    if (preview.phase === 'invalid') {
      return (
        <Alert
          type="error"
          showIcon
          icon={<CloseCircleTwoTone twoToneColor="#eb2f96" />}
          message="本地预验签未通过"
          description={preview.reason}
        />
      );
    }
    return (
      <Alert
        type={preview.verifyOk ? 'success' : 'error'}
        showIcon
        icon={
          preview.verifyOk
            ? <CheckCircleTwoTone twoToneColor="#52c41a" />
            : <CloseCircleTwoTone twoToneColor="#eb2f96" />
        }
        message={preview.verifyOk ? '本地预验签通过 ✓' : '本地预验签失败 ✗'}
        description={preview.reason}
      />
    );
  })();

  return (
    <div style={{ paddingTop: 8 }}>
      <Alert
        className="bc-rise-2"
        message="退币：把取款得到的 token 兑付到自己账户"
        description="redeem = processPayment({merchant_id: 自己, ...token})，与商户收款共享 spent_coins 表。本地预验签通过后才能提交。"
        type="info"
        showIcon
        style={{ marginBottom: 24 }}
      />

      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>粘贴 Token JSON</h2>
        <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 18 }}>
          client verify-sig · 300ms debounce
        </p>
        <Paragraph type="secondary" style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14 }}>
          token v2 形如：<span className="bc-mono bc-scalar" style={{ display: 'inline', padding: '2px 6px' }}>
            {`{ "serial": "...64hex", "amount": 30, "R_prime": "...66hex", "s_prime": "...64hex", "key_id": 1 }`}
          </span>
        </Paragraph>
        <TextArea
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          autoSize={{ minRows: 6, maxRows: 12 }}
          placeholder={`{ "serial": "...", "amount": 30, "R_prime": "...", "s_prime": "...", "key_id": 1 }`}
          style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}
        />
        <Space style={{ marginTop: 18 }}>
          <Button
            type="primary"
            onClick={handleSubmit}
            loading={submitting}
            disabled={preview.phase !== 'ok' || !preview.verifyOk}
          >
            确认退币
          </Button>
        </Space>
      </section>

      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 18 }}>本地预验签</h2>
        {previewBadge}

        {preview.phase === 'ok' && preview.token && (
          <Descriptions column={1} bordered size="small" style={{ marginTop: 16 }}>
            <Descriptions.Item label="serial (32B)">
              <Text code copyable style={{ fontSize: 12 }}>{preview.token.serial}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="amount">
              <Text strong>{preview.token.amount}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="R_prime (33B)">
              <Text code copyable style={{ fontSize: 12 }}>{preview.token.R_prime}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="s_prime (32B)">
              <Text code copyable style={{ fontSize: 12 }}>{preview.token.s_prime}</Text>
            </Descriptions.Item>
            {preview.token.key_id !== undefined && (
              <Descriptions.Item label="key_id (token v2)">
                <Text type="secondary">{preview.token.key_id}</Text>
              </Descriptions.Item>
            )}
          </Descriptions>
        )}
      </section>

      {result && (
        <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
          {result.kind === 'success' ? (
            <Result
              status="success"
              title={`+${result.deposited} BC 已退币入账`}
              subTitle={`新余额：${result.new_balance} BC`}
            />
          ) : (
            <Result
              status="error"
              title="退币失败"
              subTitle={result.msg}
            />
          )}
        </section>
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
