// components/AppLayout.jsx — M1: main layout with nav bar + role badge
//
// Renders an antd Layout with a header containing the brand, nav links, the
// current user's role badge, and a logout button. Page content renders via
// <Outlet /> from react-router.
//
// M1 keeps this minimal; later milestones add the notification center (M5)
// and the per-role menu items (/withdraw for customer, /payment for merchant).

import { Layout, Menu, Button, Space, Typography, Tag } from 'antd';
import { Link, Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

const { Header, Content } = Layout;
const { Text } = Typography;

const ROLE_META = {
  customer: { color: 'blue', label: '顾客' },
  merchant: { color: 'green', label: '商户' },
};

export default function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const roleMeta = ROLE_META[user?.role] || { color: 'default', label: user?.role };

  const menuItems = [
    { key: '/dashboard', label: <Link to="/dashboard">仪表盘</Link> },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Space size="large">
          <Text strong style={{ color: '#fff', fontSize: 18 }}>
            BlindCash
          </Text>
          <Menu
            theme="dark"
            mode="horizontal"
            selectedKeys={[location.pathname]}
            items={menuItems}
            style={{ minWidth: 120 }}
          />
        </Space>
        <Space size="middle">
          <Tag color={roleMeta.color}>{roleMeta.label}</Tag>
          <Text style={{ color: '#bbb' }}>{user?.username}</Text>
          <Button size="small" onClick={handleLogout}>退出</Button>
        </Space>
      </Header>
      <Content style={{ padding: '24px 48px' }}>
        <Outlet />
      </Content>
    </Layout>
  );
}
