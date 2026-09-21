// components/ProtectedRoute.jsx — M1: auth + optional role guard
//
// Wraps a route element; if not authed, redirects to /login.
// While AuthContext is hydrating from sessionStorage, shows a spinner.
// If a `role` prop is given and the user's role does not match, renders 403.

import { Navigate } from 'react-router-dom';
import { Spin, Result } from 'antd';
import { useAuth } from '../context/AuthContext.jsx';

export default function ProtectedRoute({ children, role: requiredRole }) {
  const { isAuthed, user, loading } = useAuth();

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" />
      </div>
    );
  }

  if (!isAuthed) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && user?.role !== requiredRole) {
    return (
      <Result
        status="403"
        title="403"
        subTitle={`此页面仅限 ${requiredRole} 角色访问，当前角色：${user?.role}`}
      />
    );
  }

  return children;
}
