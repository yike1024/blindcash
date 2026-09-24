// components/AppLayout.jsx — vault header + content shell
//
// A thin horizontal header: brand seal + wordmark, a single "首页" nav link
// (all function entries now live in the Dashboard's animated tabs),
// a role chip, the username, and a ghost logout button.
// Page content renders via <Outlet /> inside a constrained column.

import { Layout } from 'antd';
import { Link, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

const { Header, Content } = Layout;

const ROLE_META = {
  customer: { label: '顾客', chip: 'bc-chip--gold' },
  merchant: { label: '商户', chip: 'bc-chip--emerald' },
};

export default function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const roleMeta = ROLE_META[user?.role] ?? { label: user?.role, chip: '' };

  // 所有功能入口已集中到首页（Dashboard）的动画选项卡中，
  // 头部导航仅保留「首页」入口，避免与选项卡重复。
  const baseNav = [
    { to: '/dashboard', label: '首页' },
  ];
  const roleNav = [];
  const navItems = [...baseNav, ...roleNav];

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
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`bc-nav-link ${active ? 'bc-nav-link--active' : ''}`}
              >
                {item.label}
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
