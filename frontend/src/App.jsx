// App.jsx — React Router configuration
//
// M1 scope: register / login / dashboard (placeholder).
// M6 step 1: /withdraw — 4-move 取款向导.
// M6 step 2: /payment  — 粘贴 token + 预验签 + 存款 + 双花演示.
// M7: 角色解锁——任何登录用户都能取款/收款/看历史，形成 Chaum 式闭环。
//      新增 /history 账本流水页。

import { Routes, Route, Navigate } from 'react-router-dom';
import AppLayout from './components/AppLayout.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import RegisterPage from './pages/Register.jsx';
import LoginPage from './pages/Login.jsx';
import DashboardPage from './pages/Dashboard.jsx';
import WithdrawPage from './pages/Withdraw.jsx';
import PaymentPage from './pages/Payment.jsx';
import BankPage from './pages/Bank.jsx';
import WalletPage from './pages/Wallet.jsx';
import HistoryPage from './pages/History.jsx';
import PrivacyPage from './pages/Privacy.jsx';

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
        {/* Phase 1: 银行充值/退币（任何登录用户都可自助充值模拟法币入账） */}
        <Route path="/bank" element={<BankPage />} />
        {/* Phase 2: 客户端 IndexedDB 钱包（后端无感知，Chaum 匿名性关键） */}
        <Route path="/wallet" element={<WalletPage />} />
        {/* M7: 角色解锁——任何登录用户都可取款 */}
        <Route path="/withdraw" element={<WithdrawPage />} />
        {/* M7: 角色解锁——任何登录用户都可收款 */}
        <Route path="/payment" element={<PaymentPage />} />
        {/* M7: 任何登录用户都可看自己的账本流水 */}
        <Route path="/history" element={<HistoryPage />} />
        {/* Phase 6.3: 匿名集分析——按 (面额, 密钥版本) 统计不可区分性 */}
        <Route path="/privacy" element={<PrivacyPage />} />
      </Route>

      {/* Fallback */}
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
