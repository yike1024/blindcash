// context/AuthContext.jsx — M1: global auth state
//
// Provides { user, token, login, logout, isAuthed } to all pages.
// user = { id, username, role, balance }. Token + user are persisted in
// sessionStorage (per-tab isolation), so two tabs can hold independent
// sessions — required for the customer/merchant two-tab demo.

import { createContext, useContext, useState, useCallback, useEffect } from 'react';
import api from '../api/client.js';
import { resetWalletDb } from '../utils/walletDB.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  // Hydrate from sessionStorage on mount
  useEffect(() => {
    const savedToken = sessionStorage.getItem('bc_token');
    const savedUser = sessionStorage.getItem('bc_user');
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  const login = useCallback((tokenValue, userValue) => {
    sessionStorage.setItem('bc_token', tokenValue);
    sessionStorage.setItem('bc_user', JSON.stringify(userValue));
    setToken(tokenValue);
    setUser(userValue);
    // Reset the wallet DB connection so the new user's per-user database
    // (blindcash-wallet-${userValue.id}) is opened on next access.
    resetWalletDb();
  }, []);

  // M6: partial-update the cached user (e.g. after /withdraw/init debits
  // balance, /withdraw/cancel refunds). We patch sessionStorage too so the
  // state survives a tab focus change. Token is untouched.
  const updateUser = useCallback((patch) => {
    setUser((prev) => {
      if (!prev) return prev;
      const next = { ...prev, ...patch };
      sessionStorage.setItem('bc_user', JSON.stringify(next));
      return next;
    });
  }, []);

  const logout = useCallback(() => {
    sessionStorage.removeItem('bc_token');
    sessionStorage.removeItem('bc_user');
    setToken(null);
    setUser(null);
    // Reset the wallet DB connection so the next login opens the correct
    // per-user database.
    resetWalletDb();
  }, []);

  const value = {
    user,
    token,
    login,
    updateUser,
    logout,
    loading,
    isAuthed: !!token,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

// Convenience wrapper for API calls that need auth context
export function useApi() {
  return api;
}
