// App.jsx — React Router configuration
//
// M1 scope: register / login / dashboard (placeholder).
// M6 step 1: /withdraw (customer-only) — 4-move 取款向导.

import { Routes, Route, Navigate } from 'react-router-dom';
import AppLayout from './components/AppLayout.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import RegisterPage from './pages/Register.jsx';
import LoginPage from './pages/Login.jsx';
import DashboardPage from './pages/Dashboard.jsx';
import WithdrawPage from './pages/Withdraw.jsx';

export default function App() {
  return (
    <Routes>
      {/* Public routes (no nav, standalone) */}
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/login" element={<LoginPage />} />

      {/* Protected routes (auth required, with nav bar) */}
      <Route
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route path="/dashboard" element={<DashboardPage />} />
        {/* M6 step 1: customer-only 取款向导 */}
        <Route
          path="/withdraw"
          element={
            <ProtectedRoute role="customer">
              <WithdrawPage />
            </ProtectedRoute>
          }
        />
      </Route>

      {/* Fallback */}
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
