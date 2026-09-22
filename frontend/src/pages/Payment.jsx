// pages/Payment.jsx — 收款（粘贴 token → 本地预验签 → 存款）
//
// ALL CRYPTO LOGIC, DEBOUNCED PREVIEW, VERIFY-SIG FLOW PRESERVED VERBATIM.
// M7: 清除教学脚手架文案，角色锁已解锁（任何登录用户都能收款）。

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Input, Alert, Button, Space, Typography, Descriptions, Tag,
  message, Result, Spin, Collapse,
} from 'antd';
import {
  CheckCircleTwoTone, CloseCircleTwoTone, CopyOutlined, ThunderboltOutlined,
} from '@ant-design/icons';

import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';
import { verifySig } from '@crypto/client/schnorrBlindClient.js';
import { isValidCompressedFormat } from '@crypto/client/pointFormat.js';
import { hexToBytes } from '@utils/hex.js';

const { Text, Paragraph } = Typography;
const { TextArea } = Input;

const HEX64_RE = /^[0-9a-fA-F]{64}$/;

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
  return {
    ok: true,
    fields: {
      serial: tok.serial,
      amount: tok.amount,
      R_prime: tok.R_prime,
      s_prime: tok.s_prime,
    },
  };
}

function mapApiError(err, fallback = '收款失败') {
  const code = err?.response?.data?.error;
  const srvMsg = err?.response?.data?.message;
  switch (code) {
    case 'MALFORMED_TOKEN':
      return `token 字段格式错误：${srvMsg ?? ''}`;
    case 'SIGNATURE_INVALID':
      return '签名验证失败：token 被篡改或解盲错误。';
    case 'DOUBLE_SPEND':
      return '双花检测：此 token 已被花费过（serial 已在 spent_coins 表中）。';
    case 'VALIDATION_ERROR':
      return `请求参数缺失：${srvMsg ?? ''}`;
    case 'MERCHANT_NOT_FOUND':
      return '商户账户不存在（请联系管理员）。';
    default:
      return fallback;
  }
}

export default function PaymentPage() {
  const { user, updateUser } = useAuth();

  const [rawText, setRawText] = useState('');
  const [preview, setPreview] = useState({ phase: 'empty' });
  const publicKeyRef = useRef(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [lastToken, setLastToken] = useState(null);

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
            ? '本地预验签通过 (s\'·G == R\' + e\'·P)'
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
      const { data } = await api.post('/payment', preview.token);
      updateUser({ balance: data.new_balance });
      setResult({
        kind: 'success',
        msg: `已成功收款 ${data.deposited}`,
        deposited: data.deposited,
        new_balance: data.new_balance,
      });
      setLastToken(preview.token);
      message.success(`收款成功：+${data.deposited}`);
    } catch (e) {
      setResult({ kind: 'error', msg: mapApiError(e, '收款失败') });
    } finally {
      setSubmitting(false);
    }
  }, [preview, updateUser]);

  const handleResubmit = useCallback(async () => {
    if (!lastToken) return;
    setSubmitting(true);
    setResult(null);
    try {
      await api.post('/payment', lastToken);
      setResult({ kind: 'error', msg: '服务器未拒绝重复 token (异常)' });
    } catch (e) {
      const code = e?.response?.data?.error;
      if (code === 'DOUBLE_SPEND') {
        setResult({
          kind: 'error',
          msg: '✓ 双花被服务器正确检测：409 DOUBLE_SPEND (serial 已在 spent_coins 表中)',
          isDoubleSpend: true,
        });
        message.success('双花检测演示成功 (409)');
      } else {
        setResult({ kind: 'error', msg: mapApiError(e, '再次提交失败') });
      }
    } finally {
      setSubmitting(false);
    }
  }, [lastToken]);

  async function copyToken() {
    if (!preview.token) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(preview.token, null, 2));
      message.success('Token 已复制');
    } catch {
      message.error('复制失败');
    }
  }

  const previewBadge = (() => {
    if (preview.phase === 'empty') {
      return (
        <Alert
          type="info"
          showIcon
          message="将 token JSON 粘贴到下方文本框"
          description="token 来自顾客取款向导第 ④ 步：{ serial, amount, R_prime, s_prime }。本地会立即做预验签，通过后才能提交存款。"
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
        description={
          <Space direction="vertical" size="small">
            <Text>{preview.reason}</Text>
            <Text type="secondary" style={{ fontSize: 12 }}>
              本地通过 ≠ 服务器一定接受（双花/并发仍会被 409）。服务器 verifySig 是最终权威。
            </Text>
          </Space>
        }
      />
    );
  })();

  return (
    <div className="bc-page" style={{ paddingTop: 32, paddingBottom: 64 }}>
      {/* ── Page header ── */}
      <header className="bc-rise-1" style={{ marginBottom: 28 }}>
        <p className="bc-eyebrow" style={{ marginBottom: 10 }}>收款</p>
        <h1 className="bc-display" style={{ fontSize: 'clamp(32px, 4vw, 44px)', margin: 0 }}>
          粘贴 token，本地预验签后存入
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
            <span className="bc-chip bc-chip--emerald">{user?.role === 'merchant' ? '商户' : user?.role === 'customer' ? '顾客' : user?.role}</span>
          </Meta>
          <Meta label="用户名">
            <span className="bc-mono" style={{ fontSize: 14, color: 'var(--paper-100)' }}>@{user?.username}</span>
          </Meta>
        </div>
      </section>

      {/* ── Safety banner ── */}
      <Alert
        className="bc-rise-2"
        message="粘贴 token 后会自动本地预验签"
        description="通过 ✓ 后才能提交存款。服务器仍会独立做 verifySig + 双花检测，本地结果不替代服务器判定。"
        type="info"
        showIcon
        style={{ marginBottom: 24 }}
      />

      {/* ── 粘贴 token ── */}
      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>粘贴 Token JSON</h2>
        <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 18 }}>
          client verify-sig · 300ms debounce
        </p>
        <Paragraph type="secondary" style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14 }}>
          token 形如：<span className="bc-mono bc-scalar" style={{ display: 'inline', padding: '2px 6px' }}>
            {`{ "serial": "...64hex", "amount": 30, "R_prime": "...66hex", "s_prime": "...64hex" }`}
          </span>
        </Paragraph>
        <TextArea
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          autoSize={{ minRows: 6, maxRows: 12 }}
          placeholder={`{ "serial": "...", "amount": 30, "R_prime": "...", "s_prime": "..." }`}
          style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}
        />
        <Space style={{ marginTop: 18 }}>
          <Button icon={<CopyOutlined />} onClick={copyToken} disabled={preview.phase !== 'ok'}>
            复制 token
          </Button>
          <Button
            type="primary"
            onClick={handleSubmit}
            loading={submitting}
            disabled={preview.phase !== 'ok' || !preview.verifyOk}
          >
            提交存款
          </Button>
        </Space>
      </section>

      {/* ── 本地预验签 ── */}
      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>本地预验签</h2>
        <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 18 }}>
          s'·G ?= R' + e'·P
        </p>
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
          </Descriptions>
        )}
      </section>

      {/* ── 存款结果 ── */}
      {result && (
        <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
          <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 18 }}>存款结果</h2>
          {result.kind === 'success' ? (
            <Result
              status="success"
              title={`+${result.deposited} 已存入`}
              subTitle={`新余额：${result.new_balance}`}
              extra={
                <Space>
                  <Button
                    type="primary"
                    danger
                    icon={<ThunderboltOutlined />}
                    onClick={handleResubmit}
                    loading={submitting}
                  >
                    再次提交同一 token（演示双花 → 409）
                  </Button>
                </Space>
              }
            />
          ) : (
            <Result
              status={result.isDoubleSpend ? 'info' : 'error'}
              title={result.isDoubleSpend ? '双花演示成功' : '收款失败'}
              subTitle={result.msg}
              extra={
                result.isDoubleSpend ? (
                  <Alert
                    type="info"
                    showIcon
                    message="双花被服务器正确检测"
                    description={
                      <Space direction="vertical" size="small">
                        <Text>
                          本页演示「连续重复提交」——服务器必然 409 (serial 已入库)。
                        </Text>
                        <Text>
                          并发场景：两个标签页同时提交同一 token，服务器串行化，一个 200 + 一个 409，哪个赢取决于调度。
                        </Text>
                      </Space>
                    }
                  />
                ) : null
              }
            />
          )}
        </section>
      )}

      {/* ── 双花演示说明（可折叠） ── */}
      <section className="bc-card" style={{ padding: 28 }}>
        <Collapse
          ghost
          items={[{
            key: 'double-spend',
            label: <span className="bc-display" style={{ fontSize: 18 }}>关于双花演示</span>,
            children: (
              <>
                <Paragraph style={{ fontSize: 13.5, marginBottom: 12, color: 'var(--text-secondary)', lineHeight: 1.75 }}>
                  1. <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>连续重提</span>：同一 token 提交两次，
                  第二次必然 <Tag color="red">409 DOUBLE_SPEND</Tag>，
                  因 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>spent_coins.serial PRIMARY KEY</span> 已存在。
                </Paragraph>
                <Paragraph style={{ fontSize: 13.5, marginBottom: 0, color: 'var(--text-secondary)', lineHeight: 1.75 }}>
                  2. <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>双标签页并发提交</span>：两个标签页同时提交同一 token，
                  服务器 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>BEGIN IMMEDIATE</span> 串行化，
                  一个 <Tag color="green">200</Tag> + 一个 <Tag color="red">409</Tag>，
                  <Text strong style={{ color: 'var(--paper-100)' }}>具体哪个成功由调度决定，不保证先发起者赢</Text>。
                </Paragraph>
              </>
            ),
          }]}
        />
      </section>
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
