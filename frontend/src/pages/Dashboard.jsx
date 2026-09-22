// pages/Dashboard.jsx — vault-style welcome surface
//
// Renders the signed-in user a calm, legible overview: greeting, balance as
// the hero number, role/username metadata, and a single primary action that
// matches the role (取款 for customer, 收款 for merchant). All M1-era plan
// placeholders have been removed.
//
// Phase 1 (v5 §三 1.5 开户改革)：新用户 balance=0，需先到 /bank 充值才能
// 取款。余额为 0 时主 CTA 指向"银行充值"而非"取款"，避免用户撞 INSUFFICIENT_BALANCE。

import { useNavigate } from 'react-router-dom';
import { ArrowRightOutlined, SafetyOutlined, BankOutlined } from '@ant-design/icons';
import { useAuth } from '../context/AuthContext.jsx';

const ROLE_META = {
  customer: { label: '顾客', verb: '取款', route: '/withdraw', caption: '盲签名 · 4-move 切换校验' },
  merchant: { label: '商户', verb: '收款', route: '/payment', caption: '本地预验签 · 双花检测' },
};

export default function DashboardPage() {
  const { user } = useAuth();
  const navigate = useNavigate();

  const role = user?.role ?? 'customer';
  const meta = ROLE_META[role] ?? ROLE_META.customer;
  const balance = user?.balance ?? 0;
  const needsFunding = balance === 0;

  return (
    <div className="bc-page" style={{ paddingTop: 40, paddingBottom: 64 }}>
      <p className="bc-eyebrow bc-rise-1" style={{ marginBottom: 18 }}>
        BlindCash · 盲签名数字货币实验台
      </p>

      <h1 className="bc-mega bc-rise-1" style={{ marginBottom: 14 }}>
        欢迎，<span style={{ color: 'var(--gold-400)' }}>{user?.username || '匿名'}</span>。
      </h1>
      <p className="bc-rise-2" style={{ color: 'var(--text-secondary)', fontSize: 17, maxWidth: 620, margin: '0 0 36px' }}>
        本账户以 <span className="bc-mono" style={{ color: 'var(--paper-100)' }}>{meta.label}</span> 身份登记。
        {role === 'customer'
          ? '顾客可向银行发起盲签名取款，取得不可追踪的 token 后交付商户存款。'
          : '商户可粘贴顾客交付的 token，本地预验签后向银行结算入账。'}
      </p>

      <hr className="bc-hairline bc-rise-2" style={{ marginBottom: 36 }} />

      {/* ── Balance hero ── */}
      <section className="bc-card bc-rise-3" style={{ padding: '32px 36px', marginBottom: 32 }}>
        <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 24, flexWrap: 'wrap' }}>
          <div>
            <div className="bc-stat-label" style={{ marginBottom: 12 }}>账户余额</div>
            <div className="bc-num" style={{ color: 'var(--gold-400)' }}>
              {balance}
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 16, color: 'var(--text-muted)', marginLeft: 8, letterSpacing: '0.1em' }}>
                BC
              </span>
            </div>
            <div className="bc-mono" style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 10, letterSpacing: '0.06em' }}>
              {needsFunding ? 'NEW ACCOUNT · BALANCE 0 · PLEASE DEPOSIT' : 'READY FOR BLIND WITHDRAWAL'}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, alignItems: 'flex-end' }}>
            <span className={`bc-chip ${role === 'customer' ? 'bc-chip--gold' : 'bc-chip--emerald'}`}>
              {meta.label}
            </span>
            <span className="bc-mono" style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              @{user?.username}
            </span>
          </div>
        </div>
      </section>

      {/* ── Primary action card ── */}
      {/* Phase 1 (v5 §三 1.5)：余额=0 时主 CTA 指向 /bank 充值，而非取款。 */}
      <section className="bc-card bc-rise-4" style={{ padding: 0, overflow: 'hidden' }}>
        <button
          type="button"
          onClick={() => navigate(needsFunding ? '/bank' : meta.route)}
          aria-label={needsFunding ? '前往银行充值页' : `前往${meta.verb}页`}
          style={{
            appearance: 'none',
            border: 0,
            background: 'transparent',
            color: 'inherit',
            cursor: 'pointer',
            width: '100%',
            textAlign: 'left',
            padding: '28px 36px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 24,
            transition: 'background var(--dur-med) var(--ease-out)',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(229, 179, 107, 0.04)')}
          onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
        >
          <div>
            <div className="bc-eyebrow" style={{ marginBottom: 8 }}>{needsFunding ? '待办' : '下一步'}</div>
            <h2 style={{ fontSize: 28, margin: 0, display: 'inline-flex', alignItems: 'center', gap: 12 }}>
              {needsFunding ? <><BankOutlined /> 充值</> : meta.verb}
            </h2>
            <div className="bc-mono" style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
              {needsFunding ? '模拟法币入账 · 单次上限 1000 BC · 日累计 5000 BC' : meta.caption}
            </div>
          </div>
          <span
            className="bc-mono"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 10,
              fontSize: 13,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              color: 'var(--gold-400)',
              transition: 'gap var(--dur-med) var(--ease-out)',
            }}
          >
            进入
            <ArrowRightOutlined />
          </span>
        </button>
      </section>

      {/* ── Protocol primer ── */}
      <section className="bc-rise-5" style={{ marginTop: 40, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 20 }}>
        <PrimerCard
          title="盲签名"
          glyph="α·G"
          body="银行在不知晓消息内容的前提下对其签名；顾客事后解盲即得不可追踪的有效签名。"
        />
        <PrimerCard
          title="切换校验"
          glyph="N=10"
          body="顾客提交 N 个盲化候选，银行任选其一签名，要求顾客揭示其余 N-1 个的盲化因子以证未作弊。"
        />
        <PrimerCard
          title="双花检测"
          glyph="serial"
          body="每个 token 携带唯一 serial；银行将已花费 serial 记入 spent_coins 表，重花即遭拒绝。"
        />
      </section>

      <footer style={{ marginTop: 48, display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-muted)' }}>
        <SafetyOutlined style={{ color: 'var(--emerald-400)' }} />
        <span className="bc-mono" style={{ fontSize: 11, letterSpacing: '0.08em' }}>
          α/β 仅存于前端内存 · 不可追踪 · 公开可验签
        </span>
      </footer>
    </div>
  );
}

function PrimerCard({ title, glyph, body }) {
  return (
    <div className="bc-card" style={{ padding: 22 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 14 }}>
        <h3 style={{ fontSize: 20, margin: 0 }}>{title}</h3>
        <span className="bc-mono" style={{ fontSize: 12, color: 'var(--gold-400)', letterSpacing: '0.08em' }}>
          {glyph}
        </span>
      </div>
      <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: 13.5, lineHeight: 1.7 }}>
        {body}
      </p>
    </div>
  );
}
