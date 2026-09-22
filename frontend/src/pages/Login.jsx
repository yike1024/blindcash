// pages/Login.jsx — split-screen login
//
// Left column: brand manifesto with cryptographic motif. Right column: form.
// Auth flow unchanged: POST /api/auth/login { username, password } → login().

import { useState } from 'react';
import { Form, Input, Button, Alert } from 'antd';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const onFinish = async (values) => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await api.post('/auth/login', {
        username: values.username,
        password: values.password,
      });
      login(data.token, data.user);
      navigate('/dashboard');
    } catch (e) {
      const msg = e.response?.data?.message || e.response?.data?.error || '登录失败';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="bc-grid-bg"
      style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr', minHeight: '100vh', position: 'relative' }}
    >
      {/* ── Manifesto ── */}
      <aside
        className="bc-fade"
        style={{
          position: 'relative',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: 'clamp(40px, 6vw, 88px)',
          borderRight: '1px solid var(--border)',
          background:
            'radial-gradient(680px 480px at 18% 30%, rgba(229,179,107,0.10), transparent 60%),' +
            'radial-gradient(520px 400px at 90% 110%, rgba(109,184,216,0.06), transparent 60%)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 56 }}>
          <span className="bc-seal" aria-hidden="true">B</span>
          <span className="bc-display" style={{ fontSize: 21, fontWeight: 600, color: 'var(--paper-100)' }}>
            BlindCash
          </span>
        </div>

        <p className="bc-eyebrow" style={{ marginBottom: 24 }}>盲签名数字货币 · 教学实验台</p>
        <h1 className="bc-mega" style={{ fontSize: 'clamp(44px, 6vw, 76px)', marginBottom: 28 }}>
          签名所及，<br />
          <span style={{ color: 'var(--gold-400)' }}>不见来路。</span>
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 16, lineHeight: 1.75, maxWidth: 460, margin: 0 }}>
          银行在不知晓消息内容的前提下完成签名；token 可被任何持有公钥者验真，却无人能追溯其来路。
          这是 Chaum 式盲签名与 Schnorr 切换校验的最小可运行实现。
        </p>

        <div style={{ marginTop: 'auto', paddingTop: 48, display: 'flex', gap: 32, flexWrap: 'wrap' }}>
          <Metric value="secp256k1" label="曲线" />
          <Metric value="N=10" label="切换校验" />
          <Metric value="200 bit" label="盲化熵" />
        </div>
      </aside>

      {/* ── Form ── */}
      <main
        className="bc-rise"
        style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 'clamp(28px, 4vw, 56px)' }}
      >
        <div style={{ width: '100%', maxWidth: 380 }}>
          <p className="bc-eyebrow" style={{ marginBottom: 12 }}>登录</p>
          <h2 className="bc-display" style={{ fontSize: 30, marginBottom: 6 }}>回到你的金库</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 28 }}>
            登录以管理你的盲签名数字货币账户。
          </p>

          {error && (
            <Alert
              message={error}
              type="error"
              showIcon
              closable
              onClose={() => setError(null)}
              style={{ marginBottom: 20 }}
            />
          )}

          <Form layout="vertical" onFinish={onFinish} autoComplete="off" requiredMark={false}>
            <Form.Item
              name="username"
              label="用户名"
              rules={[{ required: true, message: '请输入用户名' }]}
            >
              <Input placeholder="用户名" autoComplete="username" />
            </Form.Item>

            <Form.Item
              name="password"
              label="密码"
              rules={[{ required: true, message: '请输入密码' }]}
            >
              <Input.Password placeholder="密码" autoComplete="current-password" />
            </Form.Item>

            <Button type="primary" htmlType="submit" block loading={loading} style={{ marginTop: 6 }}>
              {loading ? '正在验证…' : '登录'}
            </Button>
          </Form>

          <p className="bc-mono" style={{ textAlign: 'center', marginTop: 28, fontSize: 12, color: 'var(--text-muted)' }}>
            还没有账户？ <Link to="/register" style={{ color: 'var(--gold-400)' }}>注册 →</Link>
          </p>
        </div>
      </main>
    </div>
  );
}

function Metric({ value, label }) {
  return (
    <div>
      <div className="bc-mono" style={{ fontSize: 14, color: 'var(--gold-400)', letterSpacing: '0.04em' }}>
        {value}
      </div>
      <div className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.16em', textTransform: 'uppercase', marginTop: 4 }}>
        {label}
      </div>
    </div>
  );
}
