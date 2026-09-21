// pages/Login.jsx — M1: user login page
//
// POST /api/auth/login { username, password } → { token, user }
// On success: login() + navigate to /dashboard

import { useState } from 'react';
import { Card, Form, Input, Button, Typography, Alert, Space } from 'antd';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import api from '../api/client.js';

const { Title, Text } = Typography;

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
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', background: '#f5f7fa' }}>
      <Card style={{ width: 420, boxShadow: '0 2px 12px rgba(0,0,0,0.08)' }}>
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <Title level={3} style={{ textAlign: 'center', marginBottom: 0 }}>
            BlindCash 登录
          </Title>
          <Text type="secondary" style={{ display: 'block', textAlign: 'center' }}>
            登录以管理你的盲签名数字货币
          </Text>

          {error && <Alert message={error} type="error" showIcon closable onClose={() => setError(null)} />}

          <Form layout="vertical" onFinish={onFinish} autoComplete="off">
            <Form.Item
              name="username"
              label="用户名"
              rules={[{ required: true, message: '请输入用户名' }]}
            >
              <Input placeholder="用户名" />
            </Form.Item>

            <Form.Item
              name="password"
              label="密码"
              rules={[{ required: true, message: '请输入密码' }]}
            >
              <Input.Password placeholder="密码" />
            </Form.Item>

            <Button type="primary" htmlType="submit" block loading={loading}>
              登录
            </Button>
          </Form>

          <Text style={{ textAlign: 'center', display: 'block' }}>
            还没有账户？ <Link to="/register">去注册</Link>
          </Text>
        </Space>
      </Card>
    </div>
  );
}
