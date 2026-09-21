// api/client.js — M1: axios instance with JWT interceptor
//
// baseURL is '/api' so Vite dev proxy forwards to backend (localhost:4000).
// Request interceptor auto-attaches the JWT from sessionStorage.
// sessionStorage is per-tab → two tabs can hold two independent sessions
// (required for the "customer + merchant in two tabs" demo).
// Response interceptor auto-redirects to /login on 401.

import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

// Attach JWT to every request if present
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('bc_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// On 401, clear token + redirect to /login (unless already there)
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      sessionStorage.removeItem('bc_token');
      sessionStorage.removeItem('bc_user');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  },
);

export default api;
