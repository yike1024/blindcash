// pages/Register.jsx — M1: user registration page with role selection
//
// POST /api/auth/register { username, password, role } → { token, user }
// On success: login() + navigate to /dashboard
//
// The role Radio (customer / merchant) is the M1-defining addition over the
// cryptobank Register page. Role is immutable after registration (no
// update-role endpoint exists).

import { useState } from 'react';
import { Card, Form, Input, Button, Typography, Alert, Space, Radio } from 'antd';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';

const { Title, Text } = Typography;

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
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#f5f7fa' }}>
      <Card style={{ width: 420, boxShadow: '0 2px 12px rgba(0,0,0,0.08)' }}>
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Title level={3} style={{ textAlign: 'center', marginBottom: 0 }}>
            BlindCash 注册
          </Title>
          <Text type="secondary" style={{ display: 'block', textAlign: 'center' }}>
            创建你的盲签名数字货币账户
          </Text>

          {error && <Alert message={error} type="error" showIcon closable onClose={() => setError(null)} />}

          <Form layout="vertical" onFinish={onFinish} autoComplete="off" initialValues={{ role: 'customer' }}>
            <Form.Item
              name="username"
              label="用户名"
              rules={[
                { required: true, message: '请输入用户名' },
                { min: 3, message: '用户名至少 3 个字符' },
                { max: 20, message: '用户名最多 20 个字符' },
              ]}
            >
              <Input placeholder="用户名" />
            </Form.Item>

            <Form.Item
              name="password"
              label="密码"
              extra="至少 8 位，必须包含字母、数字和特殊字符（如 !@#$%）"
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
              <Input.Password placeholder="密码（至少 8 位，含字母+数字+特殊字符）" />
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
              <Input.Password placeholder="确认密码" />
            </Form.Item>

            <Form.Item
              name="role"
              label="角色"
              rules={[{ required: true, message: '请选择角色' }]}
              extra="角色注册后不可更改：顾客可取款，商户可收款。"
            >
              <Radio.Group>
                <Radio value="customer">顾客（取款）</Radio>
                <Radio value="merchant">商户（收款）</Radio>
              </Radio.Group>
            </Form.Item>

            <Button type="primary" htmlType="submit" block loading={loading}>
              注册
            </Button>
          </Form>

          <Text style={{ textAlign: 'center', display: 'block' }}>
            已有账户？ <Link to="/login">去登录</Link>
          </Text>
        </Space>
      </Card>
    </div>
  );
}
