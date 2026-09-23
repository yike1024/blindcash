// pages/Privacy.jsx — Phase 6.3: 匿名集分析
//
// v6 §四 6.3 落地：
//   - 从客户端 IndexedDB 钱包读取所有 token（银行不可见）
//   - 只把 key_id 列表发到 POST /api/privacy/report（不发 serial/R'/s'）
//   - 服务端用 key_id 反查 denom，统计 spent_coins 同 (denom, key_version) 数量
//   - 可视化匿名集大小 + 诚实标注隐私局限
//
// **设计哲学**：教学系统不假装提供绝对匿名。匿名集是"银行视角下至少
//   多少 token 与你的不可区分"的下界，本页面把这个下界诚实展示给用户。
//
// **隐私局限**（后端 limitations 数组直接渲染，不藏在代码里）：
//   1. 只统计已花费 token（未花费的在客户端钱包，银行不知道）
//   2. 时间侧信道（取款 vs 支付时间差）可缩小集合
//   3. 匿名集=1 意味着银行可确定关联

import { useState, useEffect, useCallback } from 'react';
import {
  Spin, Empty, Typography, message, Alert, Button, Space, Tag, Tooltip,
  Statistic, Row, Col, List,
} from 'antd';
import {
  ReloadOutlined, SafetyOutlined, WarningOutlined, EyeOutlined,
} from '@ant-design/icons';

import api from '../api/client.js';
import { listCoins } from '../utils/walletDB.js';

const { Text } = Typography;

// 匿名集等级阈值（教学化展示，非严格定义）
function anonTier(size) {
  if (size <= 1) return { label: '可追踪', color: '#f87171', bg: 'rgba(248,113,113,0.12)' };
  if (size < 10) return { label: '弱匿名', color: '#fbbf24', bg: 'rgba(251,191,36,0.12)' };
  if (size < 100) return { label: '中等匿名', color: '#60a5fa', bg: 'rgba(96,165,250,0.12)' };
  return { label: '强匿名', color: '#34d399', bg: 'rgba(52,211,153,0.12)' };
}

// 条形图最大宽度（像素）——用于相对展示匿名集大小
const BAR_MAX = 240;

export default function PrivacyPage() {
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState([]);
  const [limitations, setLimitations] = useState([]);
  const [walletCount, setWalletCount] = useState(0);
  const [reloadKey, setReloadKey] = useState(0);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // 1. 从 IndexedDB 读取所有 token（银行不可见）
      const coins = await listCoins();
      setWalletCount(coins.length);

      if (coins.length === 0) {
        setReport([]);
        setLimitations([]);
        return;
      }

      // 2. 只提取 key_id 列表发到后端（不发 serial/R'/s'）
      //    key_id 是银行公钥版本号，不是敏感信息
      const tokens = coins
        .map((c) => ({ key_id: c.key_id }))
        .filter((t) => t.key_id != null);

      if (tokens.length === 0) {
        // 钱包里有 token 但都没有 key_id（旧版 token）——无法分析
        setReport([]);
        setLimitations([
          '钱包中的 token 缺少 key_id 字段（可能是旧版 token），无法进行匿名集分析。',
        ]);
        return;
      }

      // 3. 调用后端匿名集分析接口
      const { data } = await api.post('/privacy/report', { tokens });
      setReport(data.report ?? []);
      setLimitations(data.limitations ?? []);
    } catch (e) {
      const msg = e?.response?.data?.message ?? '匿名集分析失败';
      setError(msg);
      message.error(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load, reloadKey]);

  // 汇总统计
  const summary = report.reduce((acc, row) => {
    acc.totalRows += 1;
    acc.yourTokens += row.your_tokens;
    acc.minAnon = Math.min(acc.minAnon, row.anonymity_set_size);
    acc.maxAnon = Math.max(acc.maxAnon, row.anonymity_set_size);
    return acc;
  }, { totalRows: 0, yourTokens: 0, minAnon: Infinity, maxAnon: 0 });

  const hasReport = report.length > 0;
  const maxAnonForBar = Math.max(1, ...report.map((r) => r.anonymity_set_size));

  return (
    <div className="bc-page" style={{ paddingTop: 32, paddingBottom: 64 }}>
      {/* ── 页头 ── */}
      <header className="bc-rise-1" style={{ marginBottom: 28, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <p className="bc-eyebrow" style={{ marginBottom: 10 }}>
            <SafetyOutlined style={{ marginRight: 6 }} />隐私
          </p>
          <h1 className="bc-display" style={{ fontSize: 'clamp(32px, 4vw, 44px)', margin: 0 }}>
            匿名集分析
          </h1>
        </div>
        <button
          type="button"
          className="bc-ghost-btn"
          onClick={() => setReloadKey((k) => k + 1)}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}
        >
          <ReloadOutlined />
          刷新
        </button>
      </header>

      {/* ── 说明 ── */}
      <Alert
        className="bc-rise-2"
        message="匿名集是什么？"
        description={
          <span>
            匿名集 = 银行视角下与你的 token 不可区分的 token 数量。数值越大，银行越难把你的取款和支付关联起来。
            本系统按 <Text code className="bc-mono">(面额, 密钥版本)</Text> 分组统计已花费 token——同组里所有人都混在一起。
            <br />
            <Text type="secondary" style={{ fontSize: 12 }}>
              注意：这是 <strong>下界</strong>。未花费的 token 在你浏览器里银行看不到，时间侧信道还能进一步缩小集合。
            </Text>
          </span>
        }
        type="info"
        showIcon
        style={{ marginBottom: 24 }}
      />

      {/* ── 汇总卡 ── */}
      {hasReport && !loading && (
        <Row gutter={16} className="bc-rise-2" style={{ marginBottom: 24 }}>
          <Col xs={24} sm={6}>
            <div className="bc-card" style={{ padding: 20 }}>
              <Statistic
                title="钱包 token"
                value={walletCount}
                suffix="枚"
              />
            </div>
          </Col>
          <Col xs={24} sm={6}>
            <div className="bc-card" style={{ padding: 20 }}>
              <Statistic
                title="最小匿名集"
                value={summary.minAnon === Infinity ? 0 : summary.minAnon}
                valueStyle={{ color: anonTier(summary.minAnon === Infinity ? 0 : summary.minAnon).color }}
              />
            </div>
          </Col>
          <Col xs={24} sm={6}>
            <div className="bc-card" style={{ padding: 20 }}>
              <Statistic
                title="最大匿名集"
                value={summary.maxAnon}
                valueStyle={{ color: anonTier(summary.maxAnon).color }}
              />
            </div>
          </Col>
          <Col xs={24} sm={6}>
            <div className="bc-card" style={{ padding: 20 }}>
              <Statistic
                title="密钥组数"
                value={summary.totalRows}
                suffix="组"
              />
            </div>
          </Col>
        </Row>
      )}

      {/* ── 主内容 ── */}
      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 18 }}>按 (面额, 密钥版本) 分组</h2>

        {loading ? (
          <div style={{ textAlign: 'center', padding: 48 }}><Spin tip="分析中…" /></div>
        ) : error ? (
          <Alert message={error} type="error" showIcon />
        ) : !hasReport ? (
          <Empty
            description={
              walletCount === 0
                ? '钱包为空，先去取款获得 token'
                : '无可分析的 token（可能缺少 key_id 字段）'
            }
            style={{ padding: 32 }}
          >
            {walletCount === 0 && (
              <Button type="primary" onClick={() => window.location.assign('/withdraw')}>
                去取款
              </Button>
            )}
          </Empty>
        ) : (
          <div>
            {/* ── 表头 ── */}
            <div
              className="bc-mono"
              style={{
                display: 'grid',
                gridTemplateColumns: 'minmax(80px, auto) minmax(80px, auto) minmax(180px, 1fr) minmax(120px, auto)',
                gap: 16,
                padding: '0 0 10px',
                borderBottom: '1px solid var(--border)',
                fontSize: 10,
                color: 'var(--text-muted)',
                letterSpacing: '0.12em',
                textTransform: 'uppercase',
              }}
            >
              <span>面额</span>
              <span>密钥版本</span>
              <span>匿名集大小</span>
              <span style={{ textAlign: 'right' }}>你的 token</span>
            </div>

            {/* ── 行 ── */}
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {report.map((row, idx) => {
                const tier = anonTier(row.anonymity_set_size);
                const barWidth = Math.max(4, Math.round((row.anonymity_set_size / maxAnonForBar) * BAR_MAX));
                return (
                  <li
                    key={`${row.denomination}-${row.key_version}-${idx}`}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'minmax(80px, auto) minmax(80px, auto) minmax(180px, 1fr) minmax(120px, auto)',
                      gap: 16,
                      alignItems: 'center',
                      padding: '18px 0',
                      borderBottom: '1px solid var(--border)',
                    }}
                  >
                    {/* 面额 */}
                    <span className="bc-num" style={{ fontSize: 18, color: 'var(--gold-400)', fontWeight: 600 }}>
                      {row.denomination} BC
                    </span>

                    {/* 密钥版本 */}
                    <span>
                      <Tag className="bc-mono" style={{ fontSize: 11 }}>v{row.key_version}</Tag>
                    </span>

                    {/* 条形 + 数值 */}
                    <span style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                      <div
                        aria-hidden="true"
                        style={{
                          width: `${barWidth}px`,
                          height: 14,
                          borderRadius: 4,
                          background: tier.bg,
                          border: `1px solid ${tier.color}55`,
                          position: 'relative',
                          transition: 'width var(--dur-med) var(--ease-out)',
                        }}
                      >
                        <div
                          style={{
                            position: 'absolute',
                            inset: 0,
                            borderRadius: 3,
                            background: `linear-gradient(90deg, ${tier.color}cc, ${tier.color}66)`,
                          }}
                        />
                      </div>
                      <Tooltip title={`等级：${tier.label}`}>
                        <span className="bc-num" style={{ fontSize: 18, color: tier.color, fontWeight: 600, minWidth: 36 }}>
                          {row.anonymity_set_size}
                        </span>
                      </Tooltip>
                      <Tag style={{ color: tier.color, borderColor: `${tier.color}55`, background: tier.bg }}>
                        {tier.label}
                      </Tag>
                    </span>

                    {/* 你的 token */}
                    <span style={{ textAlign: 'right' }}>
                      <span className="bc-num" style={{ fontSize: 16, color: 'var(--paper-100)' }}>
                        {row.your_tokens}
                      </span>
                      <span className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 6 }}>
                        枚
                      </span>
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </section>

      {/* ── 隐私局限（诚实文档化）── */}
      {limitations.length > 0 && !loading && (
        <section className="bc-card bc-rise-4" style={{ padding: 24, marginBottom: 24, borderColor: 'rgba(251,191,36,0.3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
            <WarningOutlined style={{ color: '#fbbf24' }} />
            <h3 className="bc-display" style={{ fontSize: 18, margin: 0 }}>隐私局限（必读）</h3>
          </div>
          <List
            size="small"
            dataSource={limitations}
            renderItem={(item, idx) => (
              <List.Item style={{ borderBottom: 'none', padding: '8px 0' }}>
                <Space align="start" style={{ alignItems: 'flex-start' }}>
                  <span className="bc-mono" style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 2 }}>
                    {String(idx + 1).padStart(2, '0')}
                  </span>
                  <Text style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.7 }}>
                    {item}
                  </Text>
                </Space>
              </List.Item>
            )}
          />
        </section>
      )}

      {/* ── 教学脚注 ── */}
      <footer style={{ marginTop: 32, display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-muted)' }}>
        <EyeOutlined style={{ color: 'var(--gold-400)' }} />
        <span className="bc-mono" style={{ fontSize: 11, letterSpacing: '0.08em' }}>
          银行视角 · 下界估计 · 不防时间侧信道
        </span>
      </footer>
    </div>
  );
}
