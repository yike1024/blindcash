// pages/Dashboard.jsx — M1: placeholder dashboard
//
// Shows account info (username / role / balance) so registration is visibly
// working. Real withdraw/payment flows arrive in M4/M5.

import { Card, Descriptions, Typography, Alert, Space } from 'antd';
import { useAuth } from '../context/AuthContext.jsx';

const { Title } = Typography;

export default function DashboardPage() {
  const { user } = useAuth();

  return (
    <Space direction="vertical" size="large" style={{ width: '100%' }}>
      <Card>
        <Title level={3} style={{ marginTop: 0 }}>仪表盘</Title>
        <Alert
          message="M1 阶段：脚手架已就绪"
          description="取款 / 收款 / 双花演示将在后续里程碑 (M2-M6) 实现。"
          type="info"
          showIcon
        />
      </Card>
      <Card title="账户信息">
        <Descriptions column={1} bordered>
          <Descriptions.Item label="用户名">{user?.username}</Descriptions.Item>
          <Descriptions.Item label="角色">
            {user?.role === 'customer' ? '顾客' : '商户'}
          </Descriptions.Item>
          <Descriptions.Item label="余额">{user?.balance ?? 0}</Descriptions.Item>
        </Descriptions>
      </Card>
    </Space>
  );
}
