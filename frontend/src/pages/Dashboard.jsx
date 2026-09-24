// pages/Dashboard.jsx — 动画选项卡首页枢纽
//
// 首页顶部使用带动画效果的选项卡组件，所有功能入口集中放置。
// 初始状态（概览 tab）仅展示余额与身份，不展示任何提示文字；
// 点击对应选项卡后，面板以淡入+上移动画平滑切换至目标功能界面。
// 各功能界面内的交互提示统一改为 CollapsibleHint 折叠面板。
//
// 动画遵循 hyperframes-keyframes 原则：有限时长、确定性延迟、
// transform/opacity 合成层属性，避免触发布局重排。

import { useState, useEffect, useRef } from 'react';
import {
  BankOutlined, WalletOutlined, ExportOutlined, ImportOutlined,
  HistoryOutlined, SafetyOutlined,
} from '@ant-design/icons';
import { useAuth } from '../context/AuthContext.jsx';
import { countPendingPayments } from '../utils/walletDB.js';

import BankPage from './Bank.jsx';
import WalletPage from './Wallet.jsx';
import WithdrawPage from './Withdraw.jsx';
import PaymentPage from './Payment.jsx';
import HistoryPage from './History.jsx';
import PrivacyPage from './Privacy.jsx';

const TABS = [
  { key: 'overview', label: '概览', icon: null },
  { key: 'bank', label: '银行', icon: <BankOutlined /> },
  { key: 'wallet', label: '钱包', icon: <WalletOutlined /> },
  { key: 'withdraw', label: '取款', icon: <ExportOutlined /> },
  { key: 'payment', label: '收款', icon: <ImportOutlined /> },
  { key: 'history', label: '历史', icon: <HistoryOutlined /> },
  { key: 'privacy', label: '隐私', icon: <SafetyOutlined /> },
];

const PANEL_MAP = {
  bank: <BankPage />,
  wallet: <WalletPage />,
  withdraw: <WithdrawPage />,
  payment: <PaymentPage />,
  history: <HistoryPage />,
  privacy: <PrivacyPage />,
};

export default function DashboardPage() {
  const { user } = useAuth();
  const [active, setActive] = useState('overview');
  const [pendingCount, setPendingCount] = useState(0);
  const tabRefs = useRef({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const count = await countPendingPayments();
        if (!cancelled) setPendingCount(count);
      } catch { /* IndexedDB unavailable */ }
    })();
    return () => { cancelled = true; };
  }, [active]);

  const activeIdx = TABS.findIndex((t) => t.key === active);

  return (
    <div className="bc-page" style={{ paddingTop: 28, paddingBottom: 64 }}>
      {/* ── 顶部余额条 + 选项卡 ── */}
      <header className="bc-rise-1" style={{ marginBottom: 24 }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-end',
            justifyContent: 'space-between',
            gap: 24,
            flexWrap: 'wrap',
            marginBottom: 28,
          }}
        >
          <div>
            <p className="bc-eyebrow" style={{ marginBottom: 10 }}>
              BlindCash · 盲签名数字货币实验台
            </p>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 14 }}>
              <span className="bc-num" style={{ color: 'var(--gold-400)' }}>
                {user?.balance ?? 0}
              </span>
              <span className="bc-mono" style={{ fontSize: 14, color: 'var(--text-muted)', letterSpacing: '0.1em' }}>
                BC
              </span>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span className={`bc-chip ${user?.role === 'merchant' ? 'bc-chip--emerald' : 'bc-chip--gold'}`}>
              {user?.role === 'merchant' ? '商户' : '顾客'}
            </span>
            <span className="bc-mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              @{user?.username}
            </span>
          </div>
        </div>

        {/* ── 动画选项卡 ── */}
        <div className="bc-tabbar" role="tablist" aria-label="功能导航">
          {TABS.map((tab, idx) => {
            const isActive = tab.key === active;
            const showBadge = tab.key === 'payment' && pendingCount > 0;
            return (
              <button
                key={tab.key}
                ref={(el) => (tabRefs.current[tab.key] = el)}
                role="tab"
                aria-selected={isActive}
                onClick={() => setActive(tab.key)}
                className={`bc-tab ${isActive ? 'bc-tab--active' : ''}`}
              >
                {tab.icon && <span className="bc-tab__icon">{tab.icon}</span>}
                <span className="bc-tab__label">{tab.label}</span>
                {showBadge && <span className="bc-tab__badge">{pendingCount}</span>}
              </button>
            );
          })}
          {/* 滑动指示器：transform 跟随激活项索引 */}
          <span
            className="bc-tabbar__indicator"
            style={{
              transform: `translateX(${activeIdx * 100}%)`,
              width: `${100 / TABS.length}%`,
            }}
            aria-hidden="true"
          />
        </div>
      </header>

      {/* ── 面板区域：key 变化触发重挂载 → 进场动画 ── */}
      <div className="bc-panel-stage">
        {active === 'overview' ? (
          <OverviewPanel key="overview" />
        ) : (
          <div key={active} className="bc-panel-enter">
            {PANEL_MAP[active]}
          </div>
        )}
      </div>
    </div>
  );
}

// ── 概览面板：仅展示余额统计，无提示文字 ──
function OverviewPanel() {
  const { user } = useAuth();
  const balance = user?.balance ?? 0;
  const needsFunding = balance === 0;

  return (
    <div className="bc-panel-enter" key="overview">
      <section
        className="bc-card"
        style={{ padding: '36px 40px', marginBottom: 24, position: 'relative', overflow: 'hidden' }}
      >
        <div
          aria-hidden="true"
          style={{
            position: 'absolute',
            top: -40,
            right: -40,
            width: 220,
            height: 220,
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(229,179,107,0.16), transparent 70%)',
            pointerEvents: 'none',
          }}
        />
        <div style={{ position: 'relative' }}>
          <div className="bc-stat-label" style={{ marginBottom: 12 }}>
            {needsFunding ? '账户待激活' : '账户余额'}
          </div>
          <div className="bc-mega" style={{ color: 'var(--gold-400)', fontSize: 'clamp(56px, 9vw, 110px)' }}>
            {balance}
          </div>
          <div className="bc-mono" style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 14, letterSpacing: '0.1em' }}>
            {needsFunding ? 'BALANCE 0 · 前往「银行」充值' : 'READY · 选择上方功能开始'}
          </div>
        </div>
      </section>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 16,
        }}
      >
        <StatTile label="身份" value={user?.role === 'merchant' ? '商户' : '顾客'} accent="var(--emerald-400)" />
        <StatTile label="用户名" value={`@${user?.username ?? '—'}`} accent="var(--cyan-400)" />
        <StatTile label="状态" value={needsFunding ? '待充值' : '就绪'} accent="var(--gold-400)" />
      </div>
    </div>
  );
}

function StatTile({ label, value, accent }) {
  return (
    <div className="bc-card" style={{ padding: '22px 24px' }}>
      <div className="bc-stat-label" style={{ marginBottom: 10 }}>{label}</div>
      <div className="bc-display" style={{ fontSize: 22, color: accent }}>{value}</div>
    </div>
  );
}
