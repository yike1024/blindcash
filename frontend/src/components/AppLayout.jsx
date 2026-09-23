// components/AppLayout.jsx — vault header + content shell
//
// A thin horizontal header: brand seal + wordmark, hairline nav with
// underline-on-active links, a role chip, the username, and a ghost logout
// button. Page content renders via <Outlet /> inside a constrained column.
//
// Phase 6.4: "收款"导航项显示待重试支付数量徽章（来自 IndexedDB
// pending_payments store）。徽章在全局导航可见，提醒用户有未完成的支付。

import { useState, useEffect } from 'react';
import { Layout } from 'antd';
import { Link, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { countPendingPayments } from '../utils/walletDB.js';

const { Header, Content } = Layout;

const ROLE_META = {
  customer: { label: '顾客', chip: 'bc-chip--gold' },
  merchant: { label: '商户', chip: 'bc-chip--emerald' },
};

export default function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [pendingCount, setPendingCount] = useState(0);

  // Phase 6.4: poll pending payments count for nav badge.
  // Re-check on route change so badge updates after retry on /payment.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const count = await countPendingPayments();
        if (!cancelled) setPendingCount(count);
      } catch {
        // IndexedDB not available — silently ignore
      }
    })();
    return () => { cancelled = true; };
  }, [location.pathname]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const roleMeta = ROLE_META[user?.role] ?? { label: user?.role, chip: '' };

  const navItems = [
    { to: '/dashboard', label: '仪表盘' },
    { to: '/bank', label: '银行' },
    { to: '/wallet', label: '钱包' },
    { to: '/withdraw', label: '取款' },
    { to: '/payment', label: '收款', badgeKey: 'payment' },
    { to: '/history', label: '历史' },
    { to: '/privacy', label: '隐私' },
  ];

  return (
    <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
      <Header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 20,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 24,
          padding: '0 clamp(20px, 4vw, 48px)',
          background: 'rgba(15, 18, 24, 0.82)',
          backdropFilter: 'blur(14px)',
          WebkitBackdropFilter: 'blur(14px)',
          borderBottom: '1px solid var(--border)',
        }}
      >
        {/* ── Brand ── */}
        <Link to="/dashboard" style={{ display: 'inline-flex', alignItems: 'center', gap: 12, textDecoration: 'none' }}>
          <span className="bc-seal" aria-hidden="true">B</span>
          <span
            className="bc-display"
            style={{ fontSize: 19, fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--paper-100)' }}
          >
            BlindCash
          </span>
        </Link>

        {/* ── Nav ── */}
        <nav style={{ display: 'flex', alignItems: 'center', gap: 28 }} aria-label="主导航">
          {navItems.map((item) => {
            const active = location.pathname === item.to;
            const showBadge = item.badgeKey === 'payment' && pendingCount > 0;
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`bc-nav-link ${active ? 'bc-nav-link--active' : ''}`}
                style={{ position: 'relative' }}
              >
                {item.label}
                {showBadge && (
                  <span
                    style={{
                      position: 'absolute',
                      top: -6,
                      right: -10,
                      backgroundColor: '#fa8c16',
                      color: '#fff',
                      fontSize: 10,
                      fontWeight: 700,
                      lineHeight: '16px',
                      minWidth: 16,
                      height: 16,
                      borderRadius: 8,
                      padding: '0 4px',
                      textAlign: 'center',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {pendingCount}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* ── Identity ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginLeft: 'auto' }}>
          <span className={`bc-chip ${roleMeta.chip}`} aria-label={`当前角色：${roleMeta.label}`}>
            {roleMeta.label}
          </span>
          <span className="bc-mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            @{user?.username}
          </span>
          <button type="button" className="bc-ghost-btn" onClick={handleLogout}>
            退出
          </button>
        </div>
      </Header>

      <Content style={{ padding: 0 }}>
        <Outlet />
      </Content>
    </Layout>
  );
}
