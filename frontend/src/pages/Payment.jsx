// pages/Payment.jsx — 收款（粘贴 token / 从钱包选 / 扫码 → 本地预验签 → 存款）
//
// M7: 角色解锁——任何登录用户都能收款。
// Phase 2 §2.3: 新增"从钱包选择"模式（radio 切换），从 IndexedDB 钱包选
//   token 自动填入。支付成功（200）后才从钱包删除该 token（按 serial 匹配）；
//   网络超时/失败 → token 保留。409 DOUBLE_SPEND 时也自动删除（审查建议 3：
//   409 = 服务端替你确认了它已花费）。
// Phase 2 §2.4: 支持扫码——离线模式 <input type=file> + jsQR 解码。

import { useState, useEffect, useRef, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Input, Alert, Button, Space, Typography, Descriptions, Tag,
  message, Result, Spin, Collapse, Radio, Select, Upload,
} from 'antd';
import {
  CheckCircleTwoTone, CloseCircleTwoTone, CopyOutlined, ThunderboltOutlined,
  ScanOutlined, WalletOutlined,
} from '@ant-design/icons';
import jsQR from 'jsqr';

import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';
import { verifySig } from '@crypto/client/schnorrBlindClient.js';
import { isValidCompressedFormat } from '@crypto/client/pointFormat.js';
import { hexToBytes } from '@utils/hex.js';
import { listCoins, getCoin, deleteCoin } from '../utils/walletDB.js';

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
  const [searchParams] = useSearchParams();

  const [inputMode, setInputMode] = useState('paste'); // 'paste' | 'wallet'
  const [rawText, setRawText] = useState('');
  const [preview, setPreview] = useState({ phase: 'empty' });
  const publicKeyRef = useRef(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [lastToken, setLastToken] = useState(null);
  const [walletCoins, setWalletCoins] = useState([]);
  const [selectedSerial, setSelectedSerial] = useState(null);

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

  // Load wallet coins when switching to wallet mode
  const loadWallet = useCallback(async () => {
    try {
      const coins = await listCoins();
      setWalletCoins(coins);
    } catch (e) {
      message.error(`加载钱包失败：${e.message}`);
    }
  }, []);

  useEffect(() => {
    if (inputMode === 'wallet') {
      loadWallet();
    }
  }, [inputMode, loadWallet]);

  // If URL has ?serial=xxx, load that coin from wallet and switch to wallet mode
  useEffect(() => {
    const serial = searchParams.get('serial');
    if (serial) {
      setInputMode('wallet');
      (async () => {
        try {
          const coin = await getCoin(serial);
          if (coin) {
            setSelectedSerial(serial);
            setRawText(JSON.stringify(coin, null, 2));
          } else {
            message.warning('钱包中未找到此 token');
          }
        } catch {
          message.warning('钱包中未找到此 token');
        }
      })();
    }
  }, [searchParams]);

  // When a wallet coin is selected, fill rawText
  const handleWalletSelect = useCallback(async (serial) => {
    setSelectedSerial(serial);
    try {
      const coin = await getCoin(serial);
      if (coin) {
        setRawText(JSON.stringify(coin, null, 2));
      }
    } catch {
      message.error('读取 token 失败');
    }
  }, []);

  // Debounced local pre-verify (shared for paste + wallet modes)
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

  // Phase 2 §2.3: 支付成功后从钱包删除该 token（按 serial 匹配）。
  // 409 DOUBLE_SPEND 时也删除——审查建议 3：409 = 服务端确认已花费，
  // 前端自动清掉，避免用户重试拿到"钱没了"的困惑。
  const removeFromWalletIfExists = useCallback(async (serial) => {
    try {
      await deleteCoin(serial);
    } catch {
      // token 不在钱包里（粘贴模式），忽略
    }
  }, []);

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
      // Phase 2: 200 成功才删 token
      await removeFromWalletIfExists(preview.token.serial);
      setResult({
        kind: 'success',
        msg: `已成功收款 ${data.deposited}`,
        deposited: data.deposited,
        new_balance: data.new_balance,
      });
      setLastToken(preview.token);
      message.success(`收款成功：+${data.deposited}`);
    } catch (e) {
      const code = e?.response?.data?.error;
      // 审查建议 3：409 = 服务端确认已花费，自动从钱包删除
      if (code === 'DOUBLE_SPEND') {
        await removeFromWalletIfExists(preview.token.serial);
      }
      setResult({ kind: 'error', msg: mapApiError(e, '收款失败') });
    } finally {
      setSubmitting(false);
    }
  }, [preview, updateUser, removeFromWalletIfExists]);

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
        await removeFromWalletIfExists(lastToken.serial);
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
  }, [lastToken, removeFromWalletIfExists]);

  async function copyToken() {
    if (!preview.token) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(preview.token, null, 2));
      message.success('Token 已复制');
    } catch {
      message.error('复制失败');
    }
  }

  // Phase 2 §2.4: 离线扫码——<input type=file> + jsQR 解码（无需 HTTPS/摄像头）
  const handleScanFile = useCallback((file) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code?.data) {
          setRawText(code.data);
          message.success('扫码成功，token 已填入');
        } else {
          message.error('未识别到二维码，请确保图片清晰');
        }
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
    return false; // prevent antd Upload default upload
  }, []);

  const previewBadge = (() => {
    if (preview.phase === 'empty') {
      return (
        <Alert
          type="info"
          showIcon
          message="将 token JSON 粘贴到下方文本框"
          description="token 来自顾客取款向导第 ④ 步：{ serial, amount, R_prime, s_prime, key_id }。本地会立即做预验签，通过后才能提交存款。"
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
      <header className="bc-rise-1" style={{ marginBottom: 28 }}>
        <p className="bc-eyebrow" style={{ marginBottom: 10 }}>收款</p>
        <h1 className="bc-display" style={{ fontSize: 'clamp(32px, 4vw, 44px)', margin: 0 }}>
          粘贴 / 扫码 / 从钱包选 token
        </h1>
      </header>

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

      <Alert
        className="bc-rise-2"
        message="选择 token 输入方式"
        description="粘贴 JSON、从钱包选择、或上传 QR 图片扫码。本地预验签通过后才能提交存款。"
        type="info"
        showIcon
        style={{ marginBottom: 24 }}
      />

      {/* ── 输入方式切换 ── */}
      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        <Radio.Group
          value={inputMode}
          onChange={(e) => setInputMode(e.target.value)}
          optionType="button"
          buttonStyle="solid"
          style={{ marginBottom: 18 }}
        >
          <Radio.Button value="paste"><CopyOutlined /> 粘贴 JSON</Radio.Button>
          <Radio.Button value="wallet"><WalletOutlined /> 从钱包选</Radio.Button>
        </Radio.Group>

        {/* 钱包选择模式 */}
        {inputMode === 'wallet' && (
          <div style={{ marginBottom: 16 }}>
            <Select
              style={{ width: '100%' }}
              placeholder="从钱包选择一个 token…"
              value={selectedSerial}
              onChange={handleWalletSelect}
              options={walletCoins.map((c) => ({
                value: c.serial,
                label: `${c.amount} BC · ${c.serial.slice(0, 12)}…${c.serial.slice(-6)}`,
              }))}
              notFoundContent="钱包为空，请先取款并存入钱包"
            />
            <Button
              size="small"
              style={{ marginTop: 8 }}
              onClick={() => { setSelectedSerial(null); setRawText(''); }}
            >
              清除选择
            </Button>
          </div>
        )}

        {/* 粘贴/扫码 */}
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>
          {inputMode === 'wallet' ? 'Token 内容' : '粘贴 Token JSON'}
        </h2>
        <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 18 }}>
          client verify-sig · 300ms debounce
        </p>

        {inputMode === 'paste' && (
          <div style={{ marginBottom: 14 }}>
            <Upload
              accept="image/*"
              showUploadList={false}
              beforeUpload={handleScanFile}
            >
              <Button icon={<ScanOutlined />}>上传 QR 图片扫码</Button>
            </Upload>
            <Text type="secondary" style={{ fontSize: 12, marginLeft: 12 }}>
              离线模式，无需摄像头/HTTPS
            </Text>
          </div>
        )}

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
            {preview.token.key_id !== undefined && (
              <Descriptions.Item label="key_id (token v2)">
                <Text type="secondary">{preview.token.key_id}</Text>
              </Descriptions.Item>
            )}
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

      {/* ── 双花演示说明 ── */}
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
