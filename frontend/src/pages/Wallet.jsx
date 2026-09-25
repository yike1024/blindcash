// pages/Wallet.jsx — Phase 2: 客户端钱包管理
//
// v5 §三 Phase 2.3 + 2.4:
//   - 列出 IndexedDB 中所有未花费 token
//   - 总余额汇总
//   - 每个 token：复制 JSON、生成 QR 码、发起支付（跳 /payment?serial=）
//   - 删除 token、清空钱包
//
// 方案 A：钱包完全在客户端，后端无 wallet 表、无 /api/wallet/* 接口。
// 银行对钱包内容完全无感知——这是 Chaum 式匿名性的关键（银行不能关联
// serial 到用户身份）。
//
// XSS 威胁模型（见 docs/DESIGN.md）：IndexedDB 明文存储，XSS 可一锅端。

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Table, Button, Space, Tag, Typography, Popconfirm, message, Empty,
  Statistic, Row, Col, Modal, Card, Input, Alert, Divider,
} from 'antd';
import {
  WalletOutlined, CopyOutlined, QrcodeOutlined,
  DeleteOutlined, ClearOutlined, LockOutlined, CheckCircleOutlined,
  CloseCircleOutlined, ReloadOutlined, SafetyCertificateOutlined,
} from '@ant-design/icons';
import QRCode from 'qrcode';

import api from '../api/client.js';
import { useAuth } from '../context/AuthContext.jsx';
import { listCoins, deleteCoin, clearAll, totalBalance } from '../utils/walletDB.js';
import CollapsibleHint from '../components/CollapsibleHint.jsx';

const { Text, Paragraph } = Typography;

export default function WalletPage() {
  const navigate = useNavigate();
  const { user, updateUser } = useAuth();
  const [coins, setCoins] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [qrModal, setQrModal] = useState({ open: false, dataUrl: '', coin: null });

  // ── 担保支付与在途交易状态 ──
  const [lockModal, setLockModal] = useState({ open: false, coin: null });
  const [escrowIdInput, setEscrowIdInput] = useState('');
  const [challengeInput, setChallengeInput] = useState('');
  const [locking, setLocking] = useState(false);
  const [escrows, setEscrows] = useState([]);
  const [loadingEscrows, setLoadingEscrows] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [list, bal] = await Promise.all([listCoins(), totalBalance()]);
      setCoins(list);
      setTotal(bal);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchEscrows = useCallback(async () => {
    setLoadingEscrows(true);
    try {
      const { data } = await api.get('/payment/escrows');
      setEscrows(data.escrows || []);
    } catch {
      // 容错
    } finally {
      setLoadingEscrows(false);
    }
    // 同步刷新账户余额：担保结算/退款会改变 users.balance，
    // 但 AuthContext 里缓存的是旧值，需要重新拉取。
    try {
      const { data: me } = await api.get('/auth/me');
      if (me?.user) updateUser({ balance: me.user.balance });
    } catch {
      // 容错
    }
  }, [updateUser]);

  useEffect(() => {
    refresh();
    fetchEscrows();
  }, [refresh, fetchEscrows]);

  const handleOpenLockModal = (coin) => {
    setLockModal({ open: true, coin });
    setEscrowIdInput('');
    setChallengeInput('');
  };

  const handleExecuteLock = async () => {
    if (!escrowIdInput.trim() || !challengeInput.trim()) {
      message.warning('请填写商户收款单号与挑战码 (Challenge)');
      return;
    }
    const coin = lockModal.coin;
    setLocking(true);
    try {
      await api.post('/payment/lock', {
        escrow_id: escrowIdInput.trim(),
        challenge: challengeInput.trim(),
        serial: coin.serial,
        amount: coin.amount,
        R_prime: coin.R_prime,
        s_prime: coin.s_prime,
        key_id: coin.key_id,
      });
      message.success('Token 已成功锁定到商户收款单！');
      // 从本地钱包删除此已锁定的 token
      await deleteCoin(coin.serial);
      setLockModal({ open: false, coin: null });
      refresh();
      fetchEscrows();
    } catch (err) {
      message.error(err?.response?.data?.message || '锁定失败');
    } finally {
      setLocking(false);
    }
  };

  const handleConfirmReceipt = async (escrowId) => {
    setActionLoadingId(escrowId);
    try {
      const { data } = await api.post('/payment/confirm', { escrow_id: escrowId });
      message.success('已确认放款至商户！交易完成。');
      // 重新获取当前用户最新余额（confirm 操作增加的是商户余额，
      // 当前用户可能是顾客，需刷新以确保余额同步）
      const { data: me } = await api.get('/auth/me');
      if (me?.user) updateUser({ balance: me.user.balance });
      fetchEscrows();
    } catch (err) {
      message.error(err?.response?.data?.message || '确认收货失败');
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleCancelEscrow = async (escrowId) => {
    setActionLoadingId(escrowId);
    try {
      const { data } = await api.post('/payment/cancel', { escrow_id: escrowId });
      message.success('托管交易已撤销，款项已退回您的账户余额！');
      // 重新获取当前用户最新余额
      const { data: me } = await api.get('/auth/me');
      if (me?.user) updateUser({ balance: me.user.balance });
      fetchEscrows();
    } catch (err) {
      message.error(err?.response?.data?.message || '撤销失败');
    } finally {
      setActionLoadingId(null);
    }
  };

  async function copyToken(coin) {
    try {
      await navigator.clipboard.writeText(JSON.stringify(coin, null, 2));
      message.success('Token 已复制');
    } catch {
      message.error('复制失败');
    }
  }

  async function showQr(coin) {
    try {
      const dataUrl = await QRCode.toDataURL(JSON.stringify(coin), {
        errorCorrectionLevel: 'M',  // 审查建议 4：密度与容错平衡
        margin: 2,
        width: 256,
      });
      setQrModal({ open: true, dataUrl, coin });
    } catch (e) {
      message.error(`QR 生成失败：${e.message}`);
    }
  }

  async function removeCoin(serial) {
    await deleteCoin(serial);
    message.success('Token 已从钱包删除');
    refresh();
  }

  async function handleClearAll() {
    await clearAll();
    message.success('钱包已清空');
    refresh();
  }

  const columns = [
    {
      title: '金额',
      dataIndex: 'amount',
      key: 'amount',
      width: 90,
      render: (v) => <Text strong style={{ color: 'var(--gold-400)' }}>{v} BC</Text>,
    },
    {
      title: 'serial',
      dataIndex: 'serial',
      key: 'serial',
      ellipsis: true,
      render: (v) => <Text code style={{ fontSize: 11 }}>{v.slice(0, 16)}…{v.slice(-8)}</Text>,
    },
    {
      title: 'key_id',
      dataIndex: 'key_id',
      key: 'key_id',
      width: 70,
      render: (v) => <Tag>{v ?? '—'}</Tag>,
    },
    {
      title: '存入时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (v) => v ? new Date(v).toLocaleString() : '—',
    },
    {
      title: '操作',
      key: 'action',
      width: 290,
      render: (_, coin) => (
        <Space size="small" wrap>
          <Button
            size="small"
            type="primary"
            style={{ background: 'var(--emerald-500)', borderColor: 'var(--emerald-500)' }}
            icon={<LockOutlined />}
            onClick={() => handleOpenLockModal(coin)}
          >
            担保锁定
          </Button>
          <Button
            size="small"
            icon={<QrcodeOutlined />}
            onClick={() => showQr(coin)}
          >
            出示
          </Button>
          <Button size="small" icon={<CopyOutlined />} onClick={() => copyToken(coin)}>复制</Button>
          <Popconfirm
            title="从此钱包删除此 Token？"
            description="删除后无法恢复。若该 token 已被花费，删除是安全的。"
            onConfirm={() => removeCoin(coin.serial)}
            okText="删除"
            cancelText="取消"
          >
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div className="bc-page" style={{ paddingTop: 32, paddingBottom: 64 }}>
      <header className="bc-rise-1" style={{ marginBottom: 28 }}>
        <p className="bc-eyebrow" style={{ marginBottom: 10 }}>
          <WalletOutlined style={{ marginRight: 6 }} />钱包
        </p>
        <h1 className="bc-display" style={{ fontSize: 'clamp(32px, 4vw, 44px)', margin: 0 }}>
          我的电子现金
        </h1>
      </header>

      <div className="bc-rise-2">
        <CollapsibleHint title="钱包存储在浏览器本地（IndexedDB）" tone="emerald">
          银行无法看到你的钱包内容——这是 Chaum 式匿名性的关键。点击「出示」生成 QR 码，让商户扫码收款。钱包按账号隔离，不同登录用户互不可见。
        </CollapsibleHint>
      </div>

      {/* ── 汇总 ── */}
      <Row gutter={16} className="bc-rise-2" style={{ marginBottom: 24 }}>
        <Col xs={24} sm={8}>
          <div className="bc-card" style={{ padding: 24 }}>
            <Statistic title="钱包总额" value={total} suffix="BC" valueStyle={{ color: 'var(--gold-400)' }} />
          </div>
        </Col>
        <Col xs={24} sm={8}>
          <div className="bc-card" style={{ padding: 24 }}>
            <Statistic title="Token 数量" value={coins.length} />
          </div>
        </Col>
        <Col xs={24} sm={8}>
          <div className="bc-card" style={{ padding: 24 }}>
            <Statistic title="单笔最大" value={coins.length ? Math.max(...coins.map(c => c.amount)) : 0} suffix="BC" />
          </div>
        </Col>
      </Row>

      {/* ── Token 列表 ── */}
      <section className="bc-card bc-rise-3" style={{ padding: 24, marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h2 className="bc-display" style={{ fontSize: 20, margin: 0 }}>Token 列表</h2>
          {coins.length > 0 && (
            <Popconfirm
              title="清空钱包？"
              description="将删除所有 token，此操作不可恢复。"
              onConfirm={handleClearAll}
              okText="清空"
              okButtonProps={{ danger: true }}
              cancelText="取消"
            >
              <Button danger icon={<ClearOutlined />}>清空钱包</Button>
            </Popconfirm>
          )}
        </div>

        {coins.length === 0 ? (
          <Empty
            description={
              <Space direction="vertical">
                <Text type="secondary">钱包为空</Text>
                <Button type="primary" onClick={() => navigate('/withdraw')}>去取款</Button>
              </Space>
            }
          />
        ) : (
          <Table
            dataSource={coins}
            columns={columns}
            rowKey="serial"
            loading={loading}
            pagination={{ pageSize: 10, showSizeChanger: false }}
            size="middle"
          />
        )}
      </section>

      {/* ── 担保交易托管区（两阶段提交防抵赖） ── */}
      <section className="bc-card bc-rise-3" style={{ padding: 24, marginBottom: 24, border: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <h2 className="bc-display" style={{ fontSize: 20, margin: 0 }}>
              <SafetyCertificateOutlined style={{ color: 'var(--emerald-400)', marginRight: 8 }} />
              担保在途交易（两阶段托管）
            </h2>
            <Text type="secondary" style={{ fontSize: 12 }}>
              锁定后资金在银行保管，商户无法直接取走。确认收货后资金打入商户；协商一致或超时可撤销退款至账户余额。
            </Text>
          </div>
          <Button onClick={fetchEscrows} loading={loadingEscrows} icon={<ReloadOutlined />}>
            刷新交易
          </Button>
        </div>

        {escrows.length === 0 ? (
          <Text type="secondary">暂无担保交易记录</Text>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {escrows.map((e) => {
              const isLocked = e.status === 'locked';
              const isCustomer = user?.id === e.customer_id;
              const isMerchant = user?.id === e.merchant_id;
              const expired = new Date(e.expires_at) < new Date();

              return (
                <div
                  key={e.id}
                  style={{
                    border: '1px solid var(--border)',
                    borderRadius: 8,
                    padding: '14px 18px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 16,
                    flexWrap: 'wrap',
                    background: isLocked ? 'rgba(82, 196, 26, 0.03)' : 'transparent',
                  }}
                >
                  <div style={{ flex: '1 1 260px' }}>
                    <Space size="middle" style={{ marginBottom: 6 }}>
                      <Text strong style={{ fontSize: 16, color: 'var(--gold-400)' }}>{e.amount} BC</Text>
                      <Tag color={
                        e.status === 'locked' ? 'orange' :
                        e.status === 'committed' ? 'green' :
                        e.status === 'cancelled' ? 'volcano' :
                        e.status === 'expired' ? 'default' : 'blue'
                      }>
                        {e.status.toUpperCase()}
                      </Tag>
                      <Text code style={{ fontSize: 11 }}>ID: {e.id.slice(0, 8)}…</Text>
                    </Space>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      商户：@{e.merchant_name} · 顾客：{e.customer_name ? `@${e.customer_name}` : '未锁定'} · 到期：{new Date(e.expires_at).toLocaleTimeString()}
                    </div>
                  </div>

                  <Space wrap>
                    {isLocked && isCustomer && (
                      <Popconfirm
                        title="确认放款给商户？"
                        description="一旦确认放款，交易即刻完成，资金将划转至商户账户，不可逆。"
                        onConfirm={() => handleConfirmReceipt(e.id)}
                        okText="确认放款"
                        cancelText="取消"
                      >
                        <Button
                          type="primary"
                          style={{ background: 'var(--emerald-500)', borderColor: 'var(--emerald-500)' }}
                          icon={<CheckCircleOutlined />}
                          loading={actionLoadingId === e.id}
                        >
                          确认收货 / 放款
                        </Button>
                      </Popconfirm>
                    )}

                    {isLocked && (isMerchant || (isCustomer && expired)) && (
                      <Popconfirm
                        title="撤销担保并退款？"
                        description="撤销后资金将立即以账户余额形式退还给顾客，Token 永久失效。"
                        onConfirm={() => handleCancelEscrow(e.id)}
                        okText="撤销并退款"
                        cancelText="取消"
                      >
                        <Button
                          danger
                          icon={<CloseCircleOutlined />}
                          loading={actionLoadingId === e.id}
                        >
                          {isMerchant ? '商户主动退款' : '超时申请退款'}
                        </Button>
                      </Popconfirm>
                    )}
                  </Space>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* ── 担保锁定模态框 ── */}
      <Modal
        open={lockModal.open}
        title="锁定 Token 到商户收款单（担保支付）"
        onCancel={() => setLockModal({ open: false, coin: null })}
        footer={
          <Space>
            <Button onClick={() => setLockModal({ open: false, coin: null })}>取消</Button>
            <Button
              type="primary"
              style={{ background: 'var(--emerald-500)', borderColor: 'var(--emerald-500)' }}
              loading={locking}
              onClick={handleExecuteLock}
            >
              确认锁定
            </Button>
          </Space>
        }
      >
        {lockModal.coin && (
          <div>
            <Alert
              type="info"
              showIcon
              message="商户挑战-响应与防盗用机制"
              description="将此 Token 唯一绑定至商户开出的单号与挑战码。锁定后其他任何人（包括网络嗅探者）均无法截获自兑，且商户必须履约才能获得放款。"
              style={{ marginBottom: 16 }}
            />
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>待锁定 Token 金额</div>
              <Text strong style={{ fontSize: 16, color: 'var(--gold-400)' }}>{lockModal.coin.amount} BC</Text>
            </div>
            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>商户收款单 ID (UUID)</div>
              <Input
                placeholder="例如：3b7c89f2-..."
                value={escrowIdInput}
                onChange={(e) => setEscrowIdInput(e.target.value)}
              />
            </div>
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>商户挑战码 (Challenge 64位十六进制)</div>
              <Input.TextArea
                rows={2}
                placeholder="粘贴商户收款单的 challenge 字符串"
                value={challengeInput}
                onChange={(e) => setChallengeInput(e.target.value)}
              />
            </div>
          </div>
        )}
      </Modal>

      {/* ── QR 模态框 ── */}
      <Modal
        open={qrModal.open}
        title="出示 Token QR 码给商户"
        onCancel={() => setQrModal({ open: false, dataUrl: '', coin: null })}
        footer={
          <Space>
            <Button onClick={() => qrModal.coin && copyToken(qrModal.coin)}>复制 Token JSON</Button>
            <Button type="primary" onClick={() => setQrModal({ open: false, dataUrl: '', coin: null })}>关闭</Button>
          </Space>
        }
      >
        {qrModal.dataUrl && (
          <div style={{ textAlign: 'center', padding: '16px 0' }}>
            <img
              src={qrModal.dataUrl}
              alt="token QR code"
              style={{ maxWidth: '100%', border: '1px solid var(--border)', padding: 12, background: '#fff' }}
            />
            <Paragraph type="secondary" style={{ marginTop: 12, fontSize: 13, lineHeight: 1.7 }}>
              <b>付款流程：</b>顾客出示此 QR → 商户在「收款」页点击「上传 QR 图片扫码」→
              本地预验签 → 提交银行 → 银行验签+查双花 → 商户余额增加。
            </Paragraph>
            <Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 0 }}>
              此过程是<b>离线</b>的——银行不参与出示环节，盲签名保证不可追踪。纠错等级 M。
            </Paragraph>
          </div>
        )}
      </Modal>
    </div>
  );
}
