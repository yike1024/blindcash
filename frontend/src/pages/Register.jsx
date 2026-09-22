// pages/Register.jsx — split-screen registration with role picker
//
// Left column: brand manifesto. Right column: form including the role Radio
// (the M1-defining addition; role is immutable after registration).

import { useState } from 'react';
import { Form, Input, Button, Alert, Radio } from 'antd';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';

export default function RegisterPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const onFinish = async (values) => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await api.post('/auth/register', {
        username: values.username,
        password: values.password,
        role: values.role,
      });
      login(data.token, data.user);
      navigate('/dashboard');
    } catch (e) {
      const msg = e.response?.data?.message || e.response?.data?.error || '注册失败';
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
        <div style={{ width: '100%', maxWidth: 400 }}>
          <p className="bc-eyebrow" style={{ marginBottom: 12 }}>注册</p>
          <h2 className="bc-display" style={{ fontSize: 30, marginBottom: 6 }}>开设你的账户</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 13, marginBottom: 28 }}>
            角色一经选定不可更改：顾客可取款，商户可收款。
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

          <Form
            layout="vertical"
            onFinish={onFinish}
            autoComplete="off"
            requiredMark={false}
            initialValues={{ role: 'customer' }}
          >
            <Form.Item
              name="username"
              label="用户名"
              rules={[
                { required: true, message: '请输入用户名' },
                { min: 3, message: '用户名至少 3 个字符' },
                { max: 20, message: '用户名最多 20 个字符' },
              ]}
            >
              <Input placeholder="用户名" autoComplete="username" />
            </Form.Item>

            <Form.Item
              name="password"
              label="密码"
              extra="至少 8 位，须含字母、数字与特殊字符（如 !@#$%）"
              rules={[
                { required: true, message: '请输入密码' },
                { min: 8, message: '密码至少 8 个字符' },
                {
                  validator: (_, value) => {
                    if (!value) return Promise.resolve();
                    if (!/[a-zA-Z]/.test(value)) return Promise.reject(new Error('密码必须包含字母'));
                    if (!/[0-9]/.test(value)) return Promise.reject(new Error('密码必须包含数字'));
                    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?~`!]/.test(value)) return Promise.reject(new Error('密码必须包含特殊字符'));
                    return Promise.resolve();
                  },
                },
              ]}
            >
              <Input.Password placeholder="至少 8 位，含字母+数字+特殊字符" autoComplete="new-password" />
            </Form.Item>

            <Form.Item
              name="confirm"
              label="确认密码"
              dependencies={['password']}
              rules={[
                { required: true, message: '请确认密码' },
                ({ getFieldValue }) => ({
                  validator(_, value) {
                    if (!value || getFieldValue('password') === value) return Promise.resolve();
                    return Promise.reject(new Error('两次输入的密码不一致'));
                  },
                }),
              ]}
            >
              <Input.Password placeholder="再次输入密码" autoComplete="new-password" />
            </Form.Item>

            <Form.Item name="role" label="角色">
              <Radio.Group buttonStyle="solid" style={{ display: 'flex', gap: 10 }}>
                <RoleOption value="customer" label="顾客" desc="取款" />
                <RoleOption value="merchant" label="商户" desc="收款" />
              </Radio.Group>
            </Form.Item>

            <Button type="primary" htmlType="submit" block loading={loading} style={{ marginTop: 6 }}>
              {loading ? '正在创建…' : '创建账户'}
            </Button>
          </Form>

          <p className="bc-mono" style={{ textAlign: 'center', marginTop: 28, fontSize: 12, color: 'var(--text-muted)' }}>
            已有账户？ <Link to="/login" style={{ color: 'var(--gold-400)' }}>登录 →</Link>
          </p>
        </div>
      </main>
    </div>
  );
}

function RoleOption({ value, label, desc }) {
  return (
    <Radio.Button
      value={value}
      style={{
        flex: 1,
        height: 'auto',
        padding: '14px 12px',
        margin: 0,
        textAlign: 'center',
        lineHeight: 1.4,
        background: 'var(--ink-600)',
        borderColor: 'var(--border)',
        color: 'var(--text-secondary)',
        borderRadius: '8px !important',
      }}
    >
      <div className="bc-display" style={{ fontSize: 17, color: 'inherit' }}>{label}</div>
      <div className="bc-mono" style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginTop: 2 }}>
        {desc}
      </div>
    </Radio.Button>
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
