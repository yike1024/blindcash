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
  Statistic, Row, Col, Modal,
} from 'antd';
import {
  WalletOutlined, CopyOutlined, QrcodeOutlined,
  DeleteOutlined, ClearOutlined,
} from '@ant-design/icons';
import QRCode from 'qrcode';

import { listCoins, deleteCoin, clearAll, totalBalance } from '../utils/walletDB.js';
import CollapsibleHint from '../components/CollapsibleHint.jsx';

const { Text, Paragraph } = Typography;

export default function WalletPage() {
  const navigate = useNavigate();
  const [coins, setCoins] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [qrModal, setQrModal] = useState({ open: false, dataUrl: '', coin: null });

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

  useEffect(() => {
    refresh();
  }, [refresh]);

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
      width: 240,
      render: (_, coin) => (
        <Space size="small" wrap>
          <Button size="small" icon={<CopyOutlined />} onClick={() => copyToken(coin)}>复制</Button>
          <Button
            size="small"
            type="primary"
            icon={<QrcodeOutlined />}
            onClick={() => showQr(coin)}
          >
            出示
          </Button>
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
      <section className="bc-card bc-rise-3" style={{ padding: 24 }}>
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
