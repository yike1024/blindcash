// pages/History.jsx — 账本流水（M7）
//
// 调 GET /api/transactions 拉当前用户的流水，按时间倒序展示。
// withdraw 红（出账）/ refund 蓝（退款入账）/ deposit 绿（收款入账）。
// 让取款去向可见，闭合"取款→转账→存款"的完整资金流。

import { useState, useEffect, useCallback } from 'react';
import { Spin, Empty, Typography, Tooltip, message } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';

const { Text, Paragraph } = Typography;

// 流水类型 → 颜色 / 方向 / 中文
const KIND_META = {
  withdraw: { label: '取款', color: 'red', sign: '-', chipClass: 'bc-chip--red' },
  deposit:  { label: '收款', color: 'green', sign: '+', chipClass: 'bc-chip--emerald' },
  refund:   { label: '退款', color: 'blue', sign: '+', chipClass: 'bc-chip--gold' },
};

function formatTime(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} `
         + `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  } catch {
    return iso;
  }
}

function shortHex(hex, head = 10, tail = 6) {
  if (!hex) return '';
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

export default function HistoryPage() {
  const { user } = useAuth();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/transactions', { params: { limit: 100 } });
      setRows(data.transactions ?? []);
    } catch (e) {
      const msg = e?.response?.data?.message ?? '拉取流水失败';
      message.error(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load, reloadKey]);

  // 汇总：净流入 = deposit + refund - withdraw
  const summary = rows.reduce((acc, r) => {
    acc.count += 1;
    const signed = r.kind === 'withdraw' ? -r.amount : r.amount;
    acc.net += signed;
    if (r.kind === 'withdraw') acc.out += r.amount;
    else if (r.kind === 'deposit') acc.in += r.amount;
    else if (r.kind === 'refund') acc.refund += r.amount;
    return acc;
  }, { count: 0, net: 0, in: 0, out: 0, refund: 0 });

  return (
    <div className="bc-page" style={{ paddingTop: 32, paddingBottom: 64 }}>
      <header className="bc-rise-1" style={{ marginBottom: 28, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <p className="bc-eyebrow" style={{ marginBottom: 10 }}>账本</p>
          <h1 className="bc-display" style={{ fontSize: 'clamp(32px, 4vw, 44px)', margin: 0 }}>
            交易流水
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

      {/* ── 汇总卡片 ── */}
      <section className="bc-card bc-rise-2" style={{ padding: '24px 28px', marginBottom: 24, display: 'flex', gap: 32, flexWrap: 'wrap', alignItems: 'center' }}>
        <SummaryBlock label="当前余额" value={user?.balance ?? 0} accent="var(--gold-400)" />
        <SummaryBlock label="累计收款" value={summary.in} accent="var(--emerald-400, #34d399)" sign="+" />
        <SummaryBlock label="累计取款" value={summary.out} accent="#f87171" sign="-" />
        <SummaryBlock label="累计退款" value={summary.refund} accent="var(--gold-300, #fbbf24)" sign="+" />
        <SummaryBlock label="流水笔数" value={summary.count} accent="var(--paper-100)" />
      </section>

      {/* ── 流水列表 ── */}
      <section className="bc-card bc-rise-3" style={{ padding: 28, marginBottom: 24 }}>
        <h2 className="bc-display" style={{ fontSize: 22, marginBottom: 18 }}>明细</h2>
        {loading ? (
          <div style={{ textAlign: 'center', padding: 48 }}><Spin tip="加载中…" /></div>
        ) : rows.length === 0 ? (
          <Empty description="暂无交易流水" style={{ padding: 32 }} />
        ) : (
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {rows.map((r) => {
              const meta = KIND_META[r.kind] ?? { label: r.kind, color: 'default', sign: '', chipClass: '' };
              const signedAmount = `${meta.sign}${r.amount}`;
              const amountColor = r.kind === 'withdraw' ? '#f87171' : (r.kind === 'refund' ? 'var(--gold-300, #fbbf24)' : 'var(--emerald-400, #34d399)');
              return (
                <li
                  key={r.id}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 18, flexWrap: 'wrap',
                    padding: '16px 0',
                    borderBottom: '1px solid var(--border)',
                  }}
                >
                  {/* 类型 chip */}
                  <span className={`bc-chip ${meta.chipClass}`} style={{ minWidth: 56, textAlign: 'center' }}>
                    {meta.label}
                  </span>
                  {/* 金额 */}
                  <span className="bc-num" style={{ fontSize: 22, color: amountColor, minWidth: 96, fontWeight: 600 }}>
                    {signedAmount}
                  </span>
                  {/* 对手方 */}
                  <span style={{ minWidth: 120 }}>
                    <span className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>
                      对手方
                    </span>
                    <Text style={{ fontSize: 13, color: 'var(--paper-100)' }}>
                      {r.counterparty ? `@${r.counterparty}` : '匿名（token）'}
                    </Text>
                  </span>
                  {/* serial 短哈希 */}
                  {r.serial_hex && (
                    <span style={{ flex: 1, minWidth: 160 }}>
                      <span className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>
                        serial
                      </span>
                      <Tooltip title={r.serial_hex}>
                        <Text code copyable={false} className="bc-mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {shortHex(r.serial_hex)}
                        </Text>
                      </Tooltip>
                    </span>
                  )}
                  {/* 备注 */}
                  {r.note && (
                    <span style={{ minWidth: 100 }}>
                      <span className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>
                        备注
                      </span>
                      <Text style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{r.note}</Text>
                    </span>
                  )}
                  {/* 时间 */}
                  <span style={{ marginLeft: 'auto', textAlign: 'right' }}>
                    <span className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>
                      时间
                    </span>
                    <Text className="bc-mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                      {formatTime(r.created_at)}
                    </Text>
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <Paragraph style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', lineHeight: 1.7 }}>
        流水按时间倒序展示（最多 100 条）。收款对手方为「匿名（token）」是 Chaum 盲现的核心特性——商户无法知道付款人身份。
      </Paragraph>
    </div>
  );
}

function SummaryBlock({ label, value, accent, sign }) {
  return (
    <div>
      <div className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 8 }}>
        {label}
      </div>
      <div className="bc-num" style={{ fontSize: 'clamp(22px, 2.5vw, 30px)', color: accent, fontWeight: 600 }}>
        {sign}{value}
      </div>
    </div>
  );
}
