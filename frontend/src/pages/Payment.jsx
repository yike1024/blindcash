// pages/Payment.jsx — M6 step 2: merchant 收款 / 双花演示
//
// v3 §5 M6 step 2 + professor's M6.md must-haves #2 & #3:
//   🟡 #3 merchant 本地预验签: 粘贴 token 后先调前端 verifySig 显示 ✓ 再提交.
//      本地预验签是 UX/教学手段 — 任何人都可公开验证盲签名 (public-verifiability).
//      但本地通过 ≠ 服务器一定接受 (双花/篡改后本地仍可能误判, 服务器 verifySig
//      是权威). 本地预验签只过滤明显的格式错误, 减少 API 调用.
//   🟡 #2 双花演示时序不确定: UI 用状态码判断, 不写"第一个一定成功".
//      真实双花 = 两个商户同时收到同一 token 并发提交, 服务器 BEGIN IMMEDIATE
//      串行化, 具体哪个 200 哪个 409 取决于调度, 不保证先发起者赢.
//      本页提供两种演示:
//        (a) 单标签页"再次提交同一 token" → 一定 409 (因 serial 已入库).
//        (b) 双标签页/双商户并发同一 token → 一边 200 一边 409 (时序不定).
//
// 流程:
//   1.TextArea 粘贴 token JSON { serial, amount, R_prime, s_prime }
//   2.useEffect debounce 300ms → 解析 JSON + 字段格式检查 + client verifySig
//   3.显示预验签结果 (✓ 通过 / ✗ 失败 + 原因)
//   4."提交存款"按钮 (disabled if 预验签未通过)
//   5.POST /api/payment → 200 (deposited, new_balance) / 400 / 409
//   6.成功后显示"再次提交同一 token"演示双花 → 409

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Card, Input, Alert, Button, Space, Typography, Descriptions, Tag,
  message, Result, Spin, Statistic, Row, Col,
} from 'antd';
import {
  CheckCircleTwoTone, CloseCircleTwoTone, CopyOutlined, ThunderboltOutlined,
} from '@ant-design/icons';

import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';
import { verifySig } from '@crypto/client/schnorrBlindClient.js';
import { isValidCompressedFormat } from '@crypto/client/pointFormat.js';
import { hexToBytes } from '@utils/hex.js';

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;

// ── helpers ────────────────────────────────────────────────────────────
const HEX64_RE = /^[0-9a-fA-F]{64}$/;

// Cheap front-end format gate mirroring backend formatGate (paymentService.js).
// Returns { ok: true, fields: {serial, amount, R_prime, s_prime} } or
//         { ok: false, reason: '...' }.
// We deliberately do NOT throw — caller renders the reason inline.
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

// Map backend PaymentError code → 中文提示.
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

// ── main component ─────────────────────────────────────────────────────
export default function PaymentPage() {
  const { user, updateUser } = useAuth();

  // raw text in the TextArea
  const [rawText, setRawText] = useState('');

  // preview state: { phase: 'empty'|'parsing'|'ok'|'invalid', reason?, token?, verifyOk? }
  const [preview, setPreview] = useState({ phase: 'empty' });

  // cached bank public key (Uint8Array 33 bytes)
  const publicKeyRef = useRef(null);

  // submit state
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null); // { kind: 'success'|'error', msg, deposited?, new_balance? }
  // double-spend demo: after first success, allow "resubmit same token"
  const [lastToken, setLastToken] = useState(null);

  // ── fetch bank public key once on mount ──
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

  // ── debounced preview: parse + format check + client verifySig ──
  useEffect(() => {
    // clear previous result whenever the raw text changes
    setResult(null);

    const text = rawText.trim();
    if (!text) {
      setPreview({ phase: 'empty' });
      return;
    }

    setPreview({ phase: 'parsing' });
    const timer = setTimeout(async () => {
      // 1. JSON parse
      let tok;
      try {
        tok = JSON.parse(text);
      } catch (e) {
        setPreview({ phase: 'invalid', reason: `JSON 解析失败：${e.message}` });
        return;
      }
      // 2. field presence + cheap format check
      if (!tok || typeof tok !== 'object') {
        setPreview({ phase: 'invalid', reason: 'token 必须是 JSON 对象' });
        return;
      }
      const fmt = cheapFormatCheck(tok);
      if (!fmt.ok) {
        setPreview({ phase: 'invalid', reason: fmt.reason });
        return;
      }
      // 3. bank public key available?
      if (!publicKeyRef.current) {
        setPreview({ phase: 'invalid', reason: '银行公钥尚未加载，请稍候再试' });
        return;
      }
      // 4. client verifySig (s'·G == R' + e'·P)
      try {
        const RPrime = hexToBytes(fmt.fields.R_prime);
        const sPrime = hexToBytes(fmt.fields.s_prime);
        // verifySig accepts s_prime as Uint8Array(32) OR bigint — we pass bytes
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

  // ── submit deposit ──
  const handleSubmit = useCallback(async () => {
    if (preview.phase !== 'ok' || !preview.verifyOk) {
      message.warning('请先粘贴并通过本地预验签');
      return;
    }
    setSubmitting(true);
    setResult(null);
    try {
      const { data } = await api.post('/payment', preview.token);
      // data = { deposited, new_balance }
      updateUser({ balance: data.new_balance });
      setResult({
        kind: 'success',
        msg: `已成功收款 ${data.deposited}`,
        deposited: data.deposited,
        new_balance: data.new_balance,
      });
      setLastToken(preview.token); // 记下来, 用于"再次提交"双花演示
      message.success(`收款成功：+${data.deposited}`);
    } catch (e) {
      setResult({ kind: 'error', msg: mapApiError(e, '收款失败') });
    } finally {
      setSubmitting(false);
    }
  }, [preview, updateUser]);

  // ── double-spend demo: resubmit the SAME token ──
  const handleResubmit = useCallback(async () => {
    if (!lastToken) return;
    setSubmitting(true);
    setResult(null);
    try {
      await api.post('/payment', lastToken);
      // 服务器应该返回 409 (没机会走到这); 但万一走到, 防御性刷新
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

  // ── render ──
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
    // phase === 'ok'
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
              本地预验签只是 UX/教学：任何人都能用银行公钥 P 验证 s'·G == R' + e'·P。
              但本地通过 ≠ 服务器一定接受（双花/并发仍会被 409）。服务器 verifySig 是最终权威。
            </Text>
          </Space>
        }
      />
    );
  })();

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Card>
        <Title level={3} style={{ marginTop: 0 }}>商户收款</Title>
        <Alert
          type="warning"
          showIcon
          message="教授 M6.md 必做 #3：本地预验签"
          description="粘贴 token 后会立即调用前端 verifySig 验证 s'·G == R' + e'·P，通过 ✓ 后才能提交存款。这只是 UX/教学手段，服务器仍会独立做 verifySig + 双花检测，本地结果不替代服务器判定。"
        />
      </Card>

      {/* 余额 */}
      <Card size="small">
        <Row gutter={16}>
          <Col flex="auto">
            <Statistic
              title="当前余额"
              value={user?.balance ?? 0}
              prefix={user?.role === 'merchant' ? '商户' : ''}
            />
          </Col>
          <Col>
            <Descriptions size="small" column={1}>
              <Descriptions.Item label="角色">
                <Tag color="green">{user?.role === 'merchant' ? '商户' : user?.role}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="用户名">{user?.username}</Descriptions.Item>
            </Descriptions>
          </Col>
        </Row>
      </Card>

      {/* 粘贴 token */}
      <Card title="粘贴 Token JSON">
        <Paragraph type="secondary" style={{ fontSize: 13 }}>
          token 形如：<Text code style={{ fontSize: 12 }}>
            {`{ "serial": "...64hex", "amount": 30, "R_prime": "...66hex", "s_prime": "...64hex" }`}
          </Text>
        </Paragraph>
        <TextArea
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          autoSize={{ minRows: 6, maxRows: 12 }}
          placeholder={`{ "serial": "...", "amount": 30, "R_prime": "...", "s_prime": "..." }`}
          style={{ fontFamily: 'monospace', fontSize: 12 }}
        />
        <Space style={{ marginTop: 12 }}>
          <Button
            icon={<CopyOutlined />}
            onClick={copyToken}
            disabled={preview.phase !== 'ok'}
          >
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
      </Card>

      {/* 预验签结果 */}
      <Card title="本地预验签" size="small">
        {previewBadge}

        {preview.phase === 'ok' && preview.token && (
          <Descriptions column={1} bordered size="small" style={{ marginTop: 12 }}>
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
      </Card>

      {/* 提交结果 */}
      {result && (
        <Card title="存款结果" size="small">
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
                    message="教授 M6.md 必做 #2：双花时序不确定"
                    description={
                      <Space direction="vertical" size="small">
                        <Text>
                          本页演示的是「单商户连续重复提交」——服务器必然 409 (因 serial 已入库)。
                        </Text>
                        <Text>
                          真实双花场景是<b>两个不同商户</b>同时收到同一 token 并发提交：
                          服务器 <Text code>BEGIN IMMEDIATE</Text> 串行化，一个 200 + 一个 409；
                          但具体哪个赢取决于调度，<b>不保证先发起者成功</b>。
                        </Text>
                        <Text>
                          想看并发版：在两个浏览器标签登录两个商户账户，粘贴同一 token，几乎同时点「提交存款」。
                        </Text>
                      </Space>
                    }
                  />
                ) : null
              }
            />
          )}
        </Card>
      )}

      {/* 双花演示说明（始终展示，便于教学） */}
      <Card size="small" title="关于双花演示">
        <Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
          <Text strong>两条路径：</Text>
        </Paragraph>
        <Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
          1. <Text code>单商户连续重提</Text>（本页直接演示）：同一 token 提交两次，
          第二次必然 <Tag color="red">409 DOUBLE_SPEND</Tag>，
          因 <Text code>spent_coins.serial PRIMARY KEY</Text> 已存在。
        </Paragraph>
        <Paragraph style={{ fontSize: 13 }}>
          2. <Text code>双商户并发提交</Text>（开两个标签页）：两个商户同时收到同一 token
          并发提交，服务器 <Text code>BEGIN IMMEDIATE</Text> 串行化，
          一个 <Tag color="green">200</Tag> + 一个 <Tag color="red">409</Tag>，
          <Text strong>具体哪个成功由调度决定，不保证先发起者赢</Text>（教授 M6.md #2）。
        </Paragraph>
      </Card>
    </Space>
  );
}
