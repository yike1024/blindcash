// components/CollapsibleHint.jsx — 点击展开式折叠面板
//
// 交互提示默认收起，仅保留简短标题；用户点击标题后平滑展开完整内容。
// 采用 grid-template-rows: 0fr → 1fr 的过渡方案（经验 1240593），
// 避免 height:auto 动画带来的布局抖动；内容区用 opacity 过渡强化层次。
//
// 遵循 hyperframes-keyframes 的 CSS keyframes 原则：有限时长、
// 确定性延迟、animation-fill-mode / transition 行为可预测。

import { useState, useCallback } from 'react';
import { DownOutlined } from '@ant-design/icons';

export default function CollapsibleHint({ title, children, defaultOpen = false, tone = 'info', action }) {
  const [open, setOpen] = useState(defaultOpen);
  const toggle = useCallback(() => setOpen((v) => !v), []);

  const toneColor = {
    info: 'var(--cyan-400)',
    gold: 'var(--gold-400)',
    emerald: 'var(--emerald-400)',
    crimson: 'var(--crimson-400)',
  }[tone] ?? 'var(--accent)';

  return (
    <div
      className="bc-collapsible"
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--r-md)',
        background: 'linear-gradient(180deg, var(--ink-600) 0%, var(--ink-700) 100%)',
        overflow: 'hidden',
        marginBottom: 24,
      }}
    >
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          padding: '14px 20px',
          background: 'transparent',
          border: 0,
          cursor: 'pointer',
          color: 'var(--text)',
          textAlign: 'left',
          transition: 'background var(--dur-fast) var(--ease-out)',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255,255,255,0.02)')}
        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
      >
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
          <span
            aria-hidden="true"
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: toneColor,
              flexShrink: 0,
            }}
          />
          <span
            className="bc-display"
            style={{ fontSize: 15, fontWeight: 600, color: 'var(--paper-100)' }}
          >
            {title}
          </span>
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
          {/* 操作区：点击不触发折叠，独立于标题按钮 */}
          {action && (
            <span
              role="presentation"
              onClick={(e) => e.stopPropagation()}
              style={{ display: 'inline-flex' }}
            >
              {action}
            </span>
          )}
          <DownOutlined
            style={{
              fontSize: 12,
              color: 'var(--text-muted)',
              transition: 'transform var(--dur-med) var(--ease-out)',
              transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
            }}
          />
        </span>
      </button>

      {/* grid-rows 0fr→1fr 过渡：内容高度自适应且无抖动 */}
      <div
        style={{
          display: 'grid',
          gridTemplateRows: open ? '1fr' : '0fr',
          transition: 'grid-template-rows var(--dur-med) var(--ease-out)',
        }}
      >
        <div style={{ overflow: 'hidden' }}>
          <div
            style={{
              padding: open ? '0 20px 18px' : '0 20px',
              opacity: open ? 1 : 0,
              transform: open ? 'translateY(0)' : 'translateY(-4px)',
              transition:
                'opacity var(--dur-med) var(--ease-out), transform var(--dur-med) var(--ease-out)',
              color: 'var(--text-secondary)',
              fontSize: 13.5,
              lineHeight: 1.7,
            }}
          >
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
