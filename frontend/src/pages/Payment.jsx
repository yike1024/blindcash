// pages/Payment.jsx — 收款（粘贴 token / 从钱包选 / 扫码 → 本地预验签 → 存款）
//
// M7: 角色解锁——任何登录用户都能收款。
// Phase 2 §2.3: 新增"从钱包选择"模式（radio 切换），从 IndexedDB 钱包选
//   token 自动填入。支付成功（200）后才从钱包删除该 token（按 serial 匹配）；
//   网络超时/失败 → token 保留。409 DOUBLE_SPEND 时也自动删除（审查建议 3：
//   409 = 服务端替你确认了它已花费）。
// Phase 2 §2.4: 支持扫码——离线模式 <input type=file> + jsQR 解码。
// Phase 6.4: 离线支付重试——网络故障时将支付暂存到 IndexedDB
//   pending_payments store，用户可手动重试。仅在可重试错误（无 response
//   = 网络中断，或 5xx 服务器错误）时暂存；4xx 永久错误（SIGNATURE_INVALID、
//   MALFORMED_TOKEN）不暂存。409 DOUBLE_SPEND 确认已花费，从 pending 和
//   wallet 双删。

import { useState, useEffect, useRef, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Input, Alert, Button, Space, Typography, Descriptions, Tag,
  message, Result, Spin, Collapse, Radio, Select, Upload, Badge,
  Card, Form, InputNumber, Modal, Divider,
} from 'antd';
import {
  CheckCircleTwoTone, CloseCircleTwoTone, CopyOutlined, ThunderboltOutlined,
  ScanOutlined, WalletOutlined, ReloadOutlined, ClockCircleOutlined,
  SafetyCertificateOutlined, QrcodeOutlined,
} from '@ant-design/icons';
import jsQR from 'jsqr';
import QRCode from 'qrcode';

import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';
import { verifySig } from '@crypto/client/schnorrBlindClient.js';
import { isValidCompressedFormat } from '@crypto/client/pointFormat.js';
import { hexToBytes } from '@utils/hex.js';
import {
  listCoins, getCoin, deleteCoin,
  addPendingPayment, listPendingPayments, deletePendingPayment,
  updatePendingPaymentAttempt,
} from '../utils/walletDB.js';
import CollapsibleHint from '../components/CollapsibleHint.jsx';

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
  // Map of key_id → public key bytes. Phase 6.1 多面额密钥：不同面额用不同
  // 密钥对签名，预验签时必须按 token.key_id 选对应公钥，否则必然失败。
  const publicKeyMapRef = useRef({});
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);
  const [lastToken, setLastToken] = useState(null);
  const [walletCoins, setWalletCoins] = useState([]);
  const [selectedSerial, setSelectedSerial] = useState(null);
  const [pendingPays, setPendingPays] = useState([]);
  const [retryingId, setRetryingId] = useState(null);

  // ── 商户担保收款单状态 ──
  const [escrowAmount, setEscrowAmount] = useState(10);
  const [escrowTtl, setEscrowTtl] = useState(300);
  const [creatingEscrow, setCreatingEscrow] = useState(false);
  const [createdEscrow, setCreatedEscrow] = useState(null);
  const [escrowQrUrl, setEscrowQrUrl] = useState('');
  const [myEscrows, setMyEscrows] = useState([]);
  const [loadingEscrows, setLoadingEscrows] = useState(false);

  const fetchMyEscrows = useCallback(async () => {
    if (user?.role !== 'merchant') return;
    setLoadingEscrows(true);
    try {
      const { data } = await api.get('/payment/escrows');
      setMyEscrows(data.escrows || []);
    } catch {
      // 容错处理
    } finally {
      setLoadingEscrows(false);
    }
    // 同步刷新账户余额：顾客 confirm 后后端已给商户入账，
    // 但 AuthContext 里缓存的 balance 是旧值，需要重新拉取。
    try {
      const { data: me } = await api.get('/auth/me');
      if (me?.user) updateUser({ balance: me.user.balance });
    } catch {
      // 容错处理
    }
  }, [user?.role, updateUser]);

  useEffect(() => {
    fetchMyEscrows();
  }, [fetchMyEscrows]);

  const handleCreateEscrow = async () => {
    setCreatingEscrow(true);
    try {
      const { data } = await api.post('/payment/escrow', {
        amount: escrowAmount,
        denomination: escrowAmount,
        ttl_seconds: escrowTtl,
      });
      setCreatedEscrow(data);
      message.success('担保收款单创建成功');
      fetchMyEscrows();
      // 生成包含 escrow_id 与 challenge 的快捷二维码
      try {
        const qrContent = JSON.stringify({
          type: 'blindcash_escrow',
          escrow_id: data.escrow_id,
          challenge: data.challenge,
          amount: data.amount,
        });
        const url = await QRCode.toDataURL(qrContent, { margin: 2, width: 220 });
        setEscrowQrUrl(url);
      } catch (err) {
        console.error('生成收款二维码失败', err);
      }
    } catch (err) {
      message.error(err?.response?.data?.message || '创建收款单失败');
    } finally {
      setCreatingEscrow(false);
    }
  };

  const handleMerchantCancelEscrow = async (escrowId) => {
    try {
      await api.post('/payment/cancel', { escrow_id: escrowId });
      message.success('收款单已撤销/退款');
      // 重新获取当前用户最新余额
      const { data: me } = await api.get('/auth/me');
      if (me?.user) updateUser({ balance: me.user.balance });
      fetchMyEscrows();
    } catch (err) {
      message.error(err?.response?.data?.message || '撤销失败');
    }
  };

  // Load bank public keys for local pre-verify.
  // Phase 6.1 多面额密钥：fetch /bank/pubkeys (plural) 拿到所有面额的
  // { key_id → public_key } 映射。预验签时按 token.key_id 选对应公钥，
  // 否则非 denom=1 的 token 会因公钥不匹配而预验签失败。
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { data } = await api.get('/bank/pubkeys');
        if (cancelled) return;
        const map = {};
        for (const info of Object.values(data.denominations)) {
          map[info.key_id] = hexToBytes(info.public_key);
        }
        publicKeyMapRef.current = map;
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

  // Phase 6.4: Load pending payments on mount + after submit/retry
  const loadPending = useCallback(async () => {
    try {
      const pending = await listPendingPayments();
      setPendingPays(pending);
    } catch (e) {
      message.error(`加载待重试支付失败：${e.message}`);
    }
  }, []);

  useEffect(() => {
    loadPending();
  }, [loadPending]);

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
      // 按 token.key_id 选对应面额的公钥；缺 key_id 时取映射中第一个（前向兼容）
      const keyMap = publicKeyMapRef.current;
      const keyIds = Object.keys(keyMap);
      if (keyIds.length === 0) {
        setPreview({ phase: 'invalid', reason: '银行公钥尚未加载，请稍候再试' });
        return;
      }
      const pubKey = fmt.fields.key_id !== undefined
        ? keyMap[fmt.fields.key_id]
        : keyMap[keyIds[0]];
      if (!pubKey) {
        setPreview({ phase: 'invalid', reason: `未找到 key_id=${fmt.fields.key_id} 对应的银行公钥（可能密钥已轮换）` });
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
          pubKey,
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
      const status = e?.response?.status;

      // 审查建议 3：409 = 服务端确认已花费，自动从钱包删除
      if (code === 'DOUBLE_SPEND') {
        await removeFromWalletIfExists(preview.token.serial);
        setResult({
          kind: 'error',
          msg: '双花检测：此 token 已被花费过（serial 已在 spent_coins 表中）。',
        });
        return;
      }

      // Phase 6.4: 网络故障或 5xx 服务器错误 → 暂存到 pending_payments
      // 可重试条件：无 response（axios 网络错误）或 status >= 500 或 429
      const isRetryable = !e.response || (status >= 500 && status < 600) || status === 429;
      if (isRetryable) {
        const errMsg = e.response
          ? `服务器错误 ${status}：${e.response.data?.message ?? e.message}`
          : `网络错误：${e.message ?? '无法连接服务器'}`;
        await addPendingPayment(preview.token, errMsg);
        await loadPending();
        setResult({
          kind: 'pending',
          msg: `网络故障，支付已暂存（${errMsg}）。请在下方"待重试支付"区手动重试。`,
        });
        message.warning('支付已暂存，待网络恢复后重试');
        return;
      }

      setResult({ kind: 'error', msg: mapApiError(e, '收款失败') });
    } finally {
      setSubmitting(false);
    }
  }, [preview, updateUser, removeFromWalletIfExists, loadPending]);

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

  // Phase 6.4: Retry a pending payment. Re-submit the stored token to /payment.
  // On success (200): delete from pending + wallet, update balance.
  // On 409 DOUBLE_SPEND: delete from pending + wallet (confirmed spent).
  // On 4xx permanent error (MALFORMED/SIGNATURE): delete from pending (no retry value).
  // On network/5xx: increment attempts + update last_error, keep pending.
  const handleRetryPending = useCallback(async (pendingId) => {
    setRetryingId(pendingId);
    try {
      const pending = pendingPays.find((p) => p.id === pendingId);
      if (!pending) {
        message.error('待重试支付不存在');
        return;
      }
      const token = pending.token;
      const { data } = await api.post('/payment', token);
      // Success → delete from pending + wallet, update balance
      updateUser({ balance: data.new_balance });
      await deletePendingPayment(pendingId);
      await removeFromWalletIfExists(token.serial);
      await loadPending();
      setResult({
        kind: 'success',
        msg: `重试成功：已收款 ${data.deposited}`,
        deposited: data.deposited,
        new_balance: data.new_balance,
      });
      message.success(`重试成功：+${data.deposited}`);
    } catch (e) {
      const code = e?.response?.data?.error;
      const status = e?.response?.status;

      if (code === 'DOUBLE_SPEND') {
        // Token already spent — confirmed by server, no point retrying
        await deletePendingPayment(pendingId);
        await removeFromWalletIfExists(
          pendingPays.find((p) => p.id === pendingId)?.token?.serial,
        );
        await loadPending();
        message.info('此 token 已被花费，从待重试列表移除');
        return;
      }

      // Permanent 4xx errors (except 429 rate-limit) → remove from pending
      const isPermanent = e.response && status >= 400 && status < 500 && status !== 429;
      if (isPermanent) {
        await deletePendingPayment(pendingId);
        await loadPending();
        message.error(`永久错误 ${status}，已从待重试列表移除：${e.response.data?.message ?? e.message}`);
        return;
      }

      // Network/5xx → increment attempts, keep pending
      const errMsg = e.response
        ? `服务器错误 ${status}：${e.response.data?.message ?? e.message}`
        : `网络错误：${e.message ?? '无法连接服务器'}`;
      await updatePendingPaymentAttempt(pendingId, errMsg);
      await loadPending();
      message.warning(`重试失败：${errMsg}`);
    } finally {
      setRetryingId(null);
    }
  }, [pendingPays, updateUser, removeFromWalletIfExists, loadPending]);

  // Phase 6.4: Discard a pending payment (user gives up)
  const handleDiscardPending = useCallback(async (pendingId) => {
    await deletePendingPayment(pendingId);
    await loadPending();
    message.info('已移除待重试支付');
  }, [loadPending]);

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
        <CollapsibleHint title="将 token JSON 粘贴到下方文本框" tone="info">
          token 来自顾客取款向导第 ④ 步：{'{ serial, amount, R_prime, s_prime, key_id }'}。本地会立即做预验签，通过后才能提交存款。
        </CollapsibleHint>
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

  const isMerchant = user?.role === 'merchant';

  return (
    <div className="bc-page" style={{ paddingTop: 32, paddingBottom: 64 }}>
      <header className="bc-rise-1" style={{ marginBottom: 28 }}>
        <p className="bc-eyebrow" style={{ marginBottom: 10 }}>{isMerchant ? '商户收款' : '存入 token'}</p>
        <h1 className="bc-display" style={{ fontSize: 'clamp(32px, 4vw, 44px)', margin: 0 }}>
          {isMerchant ? '接收顾客支付的 token' : '粘贴 / 扫码 / 从钱包选 token'}
        </h1>
        {!isMerchant && (
          <p style={{ marginTop: 8, color: 'var(--text-secondary)', fontSize: 14 }}>
            顾客从「钱包」页出示 QR 码后，你在此粘贴或扫码存入。
          </p>
        )}
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

      {/* ── Chaum 盲签名付款流程图（参照课程 PPT §3.1 系统架构） ── */}
      <section className="bc-card bc-rise-2" style={{ padding: 28, marginBottom: 24 }}>
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>Chaum 盲签名付款流程</h2>
        <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 18 }}>
          D. Chaum 1982 · 离线电子现金 & 担保托管协议
        </p>
        <div style={{ display: 'flex', alignItems: 'stretch', gap: 0, flexWrap: 'wrap', marginBottom: 16 }}>
          {[
            { num: '❶', who: '顾客', act: '取款', detail: '银行盲签名\n4-move 切换校验', color: 'gold' },
            { num: '❷', who: '商户', act: '开收款单', detail: '生成 Challenge\n随机数与有效期', color: 'cyan' },
            { num: '❸', who: '顾客', act: '锁定 Token', detail: '两阶段占位\n防截获盗兑', color: 'emerald' },
            { num: '❹', who: '顾客', act: '确认收货', detail: '仅顾客本人权限\n放款结算至商户', color: 'gold' },
            { num: '❺', who: '银行', act: '双花与状态', detail: 'serial 查 spent_coins\n准备金严格守恒', color: 'crimson' },
            { num: '❻', who: '商户/顾客', act: '结算或退款', detail: 'confirm入账商户\ncancel退还顾客', color: 'emerald' },
          ].map((s, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', flex: '1 1 0', minWidth: 140 }}>
              <div style={{
                flex: 1, padding: '12px 10px', borderRadius: 'var(--r-sm)',
                background: 'var(--ink-700)', border: '1px solid var(--border)',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: 18, marginBottom: 4 }}>{s.num}</div>
                <div className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>{s.who}</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: `var(--${s.color}-400)`, marginBottom: 4 }}>{s.act}</div>
                <div className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'pre-line', lineHeight: 1.4 }}>{s.detail}</div>
              </div>
              {i < 5 && <div style={{ color: 'var(--text-muted)', fontSize: 14, padding: '0 4px' }}>→</div>}
            </div>
          ))}
        </div>
        <Alert
          type="info"
          showIcon
          message="防盗用与防抵赖：商户挑战-响应 + 在线担保托管"
          description={
            <span style={{ fontSize: 13 }}>
              传统 Chaum eCash 依赖纯离线持有者模型，存在网络嗅探盗用与履约抵赖风险。本系统引入<b>商户挑战码（Challenge）</b>将支付与交易单唯一绑定，并采用<b>两阶段托管（Lock → Confirm/Cancel）</b>实现原子履约。
            </span>
          }
        />
      </section>

      {/* ── 商户专属：担保收款单管理 ── */}
      {isMerchant && (
        <section className="bc-card bc-rise-2" style={{ padding: 28, marginBottom: 24, border: '1px solid var(--emerald-500)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h2 className="bc-display" style={{ fontSize: 22, margin: 0 }}>
                <SafetyCertificateOutlined style={{ color: 'var(--emerald-400)', marginRight: 8 }} />
                发起担保收款单（挑战-响应防盗用）
              </h2>
              <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', marginTop: 4, marginBottom: 0 }}>
                Two-Phase Escrow · Merchant Challenge-Response
              </p>
            </div>
            <Button onClick={fetchMyEscrows} loading={loadingEscrows} icon={<ReloadOutlined />}>
              刷新单据
            </Button>
          </div>

          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'flex-start' }}>
            <div style={{ flex: '1 1 320px', minWidth: 280 }}>
              <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginBottom: 16 }}>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>收款金额 (BC)</div>
                  <InputNumber min={1} value={escrowAmount} onChange={(v) => setEscrowAmount(v || 1)} style={{ width: 140 }} />
                </div>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>有效时间 (秒)</div>
                  <InputNumber min={30} max={86400} value={escrowTtl} onChange={(v) => setEscrowTtl(v || 300)} style={{ width: 140 }} />
                </div>
                <div style={{ alignSelf: 'flex-end' }}>
                  <Button type="primary" onClick={handleCreateEscrow} loading={creatingEscrow} style={{ background: 'var(--emerald-500)', borderColor: 'var(--emerald-500)' }}>
                    生成收款单
                  </Button>
                </div>
              </div>

              {createdEscrow && (
                <Alert
                  type="success"
                  message="当前有效收款单"
                  description={
                    <div style={{ marginTop: 8 }}>
                      <div><b>单号 ID：</b> <Text code copyable>{createdEscrow.escrow_id}</Text></div>
                      <div style={{ marginTop: 4 }}><b>金额：</b> <Text strong style={{ color: 'var(--gold-400)' }}>{createdEscrow.amount} BC</Text></div>
                      <div style={{ marginTop: 4 }}><b>挑战码 (Challenge)：</b></div>
                      <Paragraph copyable style={{ fontSize: 11, fontFamily: 'monospace', wordBreak: 'break-all', marginBottom: 6 }}>
                        {createdEscrow.challenge}
                      </Paragraph>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        将此挑战码或下方二维码展示给顾客，顾客在钱包中绑定此单号锁定支付。
                      </Text>
                    </div>
                  }
                  style={{ marginBottom: 16 }}
                />
              )}
            </div>

            {escrowQrUrl && (
              <div style={{ textAlign: 'center', border: '1px solid var(--border)', borderRadius: 8, padding: 14, background: '#fff' }}>
                <img src={escrowQrUrl} alt="escrow qr" style={{ width: 180, height: 180 }} />
                <div style={{ color: '#333', fontSize: 12, marginTop: 6, fontWeight: 600 }}>扫码绑定收款单</div>
              </div>
            )}
          </div>

          <Divider style={{ margin: '20px 0' }} />

          <h3 style={{ fontSize: 16, marginBottom: 12 }}>我创建的收款单</h3>
          {myEscrows.length === 0 ? (
            <Text type="secondary">暂无收款单记录</Text>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {myEscrows.slice(0, 5).map((e) => (
                <div key={e.id} style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                  <div>
                    <Space>
                      <Text strong>{e.amount} BC</Text>
                      <Tag color={
                        e.status === 'created' ? 'blue' :
                        e.status === 'locked' ? 'orange' :
                        e.status === 'committed' ? 'green' : 'default'
                      }>
                        {e.status.toUpperCase()}
                      </Tag>
                      <Text type="secondary" style={{ fontSize: 11 }}>ID: {e.id.slice(0, 8)}…</Text>
                    </Space>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                      到期：{new Date(e.expires_at).toLocaleTimeString()} · 顾客：{e.customer_name ? `@${e.customer_name}` : '未锁定'}
                    </div>
                  </div>
                  <div>
                    {['created', 'locked'].includes(e.status) && (
                      <Button size="small" danger onClick={() => handleMerchantCancelEscrow(e.id)}>
                        {e.status === 'locked' ? '退还顾客' : '撤销收款单'}
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* ── 输入 token ── */}
      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        {/* 顾客才有钱包选择模式；商户只有粘贴/扫码 */}
        {!isMerchant && (
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
        )}

        {/* 钱包选择模式（仅顾客） */}
        {!isMerchant && inputMode === 'wallet' && (
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

        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 4 }}>
          {isMerchant ? '粘贴 / 扫码 收取 token' : (inputMode === 'wallet' ? 'Token 内容' : '粘贴 Token JSON')}
        </h2>
        <p className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 18 }}>
          client verify-sig · 300ms debounce · s'·G ?= R' + e'·P
        </p>

        {(isMerchant || inputMode === 'paste') && (
          <div style={{ marginBottom: 14 }}>
            <Upload
              accept="image/*"
              showUploadList={false}
              beforeUpload={handleScanFile}
            >
              <Button icon={<ScanOutlined />}>上传 QR 图片扫码</Button>
            </Upload>
            <Text type="secondary" style={{ fontSize: 12, marginLeft: 12 }}>
              顾客从钱包页「出示」生成 QR 码 → 你在此扫码
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
          style={{ fontFamily: 'var(--font-mono)', fontSize: 12, border: '1px solid var(--border-strong)' }}
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
          ) : result.kind === 'pending' ? (
            <Result
              status="warning"
              icon={<ClockCircleOutlined />}
              title="支付已暂存"
              subTitle={result.msg}
              extra={
                <Alert
                  type="info"
                  showIcon
                  message="离线支付重试"
                  description="Token 仍在钱包中未被消费。网络恢复后可在下方「待重试支付」区手动重试，或关闭页面稍后回来——pending 记录持久化在 IndexedDB。"
                />
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

      {/* ── Phase 6.4: 待重试支付 ── */}
      {pendingPays.length > 0 && (
        <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
            <Badge count={pendingPays.length} style={{ backgroundColor: '#fa8c16' }} />
            <h2 className="bc-display" style={{ fontSize: 22, margin: 0 }}>待重试支付</h2>
          </div>
          <Alert
            type="warning"
            showIcon
            message="以下支付因网络故障暂存，请手动重试"
            description="网络恢复后点击「重试」重新提交。如果服务器返回 409（已花费）或 4xx（永久错误），将自动从列表移除。"
            style={{ marginBottom: 18 }}
          />
          <Space direction="vertical" style={{ width: '100%' }} size="middle">
            {pendingPays.map((p) => (
              <div
                key={p.id}
                style={{
                  border: '1px solid var(--border)',
                  borderRadius: 8,
                  padding: '14px 18px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 16,
                  flexWrap: 'wrap',
                }}
              >
                <div style={{ minWidth: 200, flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <Text strong style={{ fontSize: 16 }}>{p.token.amount}</Text>
                    <span className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.1em' }}>BC</span>
                    <Tag color="orange">尝试 {p.attempts ?? 0} 次</Tag>
                  </div>
                  <Text type="secondary" style={{ fontSize: 12 }} className="bc-mono">
                    {p.token.serial.slice(0, 16)}…{p.token.serial.slice(-8)}
                  </Text>
                  {p.last_error && (
                    <div style={{ marginTop: 6 }}>
                      <Text type="danger" style={{ fontSize: 11 }}>{p.last_error}</Text>
                    </div>
                  )}
                </div>
                <Space>
                  <Button
                    type="primary"
                    icon={<ReloadOutlined />}
                    loading={retryingId === p.id}
                    onClick={() => handleRetryPending(p.id)}
                  >
                    重试
                  </Button>
                  <Button
                    danger
                    onClick={() => handleDiscardPending(p.id)}
                    disabled={retryingId === p.id}
                  >
                    丢弃
                  </Button>
                </Space>
              </div>
            ))}
          </Space>
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
