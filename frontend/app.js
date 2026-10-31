/**
 * app.js — Shared helper untuk semua halaman frontend
 * Mengelola token, device ID, fetch wrapper, dan logout.
 */

const API_BASE = 'http://localhost:3000';

// ─── DEVICE ID ────────────────────────────────────────────────────────────────
// Di-generate sekali dan disimpan di localStorage agar persisten.

function getDeviceId() {
  let id = localStorage.getItem('zt_device_id');
  if (!id) {
    id = 'device-' + Math.random().toString(36).slice(2, 10) + '-' + Date.now().toString(36);
    localStorage.setItem('zt_device_id', id);
  }
  return id;
}

// ─── TOKEN ────────────────────────────────────────────────────────────────────

function getToken() {
  return sessionStorage.getItem('zt_token');
}

function setToken(token) {
  sessionStorage.setItem('zt_token', token);
}

function getUser() {
  try {
    return JSON.parse(sessionStorage.getItem('zt_user') || 'null');
  } catch { return null; }
}

function setUser(user) {
  sessionStorage.setItem('zt_user', JSON.stringify(user));
}

function clearSession() {
  sessionStorage.removeItem('zt_token');
  sessionStorage.removeItem('zt_refresh');
  sessionStorage.removeItem('zt_user');
}

function getRefreshToken() {
  return sessionStorage.getItem('zt_refresh');
}

function setRefreshToken(token) {
  sessionStorage.setItem('zt_refresh', token);
}

// ─── AUTH HEADERS ─────────────────────────────────────────────────────────────

function authHeaders(extra = {}) {
  return {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${getToken()}`,
    'X-Device-ID': getDeviceId(),
    ...extra
  };
}

// ─── FETCH WRAPPER ────────────────────────────────────────────────────────────
// Otomatis kirim auth headers. Jika 401 → redirect ke login.

async function apiFetch(path, options = {}) {
  const url = API_BASE + path;
  const defaults = {
    headers: authHeaders(),
  };
  const merged = {
    ...defaults,
    ...options,
    headers: { ...defaults.headers, ...(options.headers || {}) }
  };

  let res;
  try {
    res = await fetch(url, merged);
  } catch (err) {
    throw new Error('Tidak dapat terhubung ke server. Pastikan gateway berjalan di port 3000.');
  }

  // Token expired atau invalid → coba refresh sekali
  if (res.status === 401) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      merged.headers['Authorization'] = `Bearer ${getToken()}`;
      res = await fetch(url, merged);
    } else {
      clearSession();
      window.location.href = '/index.html';
      return null;
    }
  }

  const data = await res.json();
  return { status: res.status, ok: res.ok, data };
}

// ─── REFRESH TOKEN ────────────────────────────────────────────────────────────

async function tryRefresh() {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return false;

  try {
    const res = await fetch(API_BASE + '/auth/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': getDeviceId()
      },
      body: JSON.stringify({ refresh_token: refreshToken })
    });
    if (!res.ok) return false;
    const data = await res.json();
    if (data.success) {
      setToken(data.data.access_token);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// ─── LOGOUT ───────────────────────────────────────────────────────────────────

async function logout() {
  const token = getToken();
  const refreshToken = getRefreshToken();

  try {
    await fetch(API_BASE + '/auth/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        'X-Device-ID': getDeviceId()
      },
      body: JSON.stringify({ refresh_token: refreshToken })
    });
  } catch { /* tetap logout meski request gagal */ }

  clearSession();
  window.location.href = '/index.html';
}

// ─── GUARD: pastikan sudah login dan role sesuai ──────────────────────────────

function requireAuth(expectedRole = null) {
  const token = getToken();
  const user  = getUser();

  if (!token || !user) {
    window.location.href = '/index.html';
    return false;
  }

  if (expectedRole && user.role !== expectedRole) {
    // Role tidak sesuai → arahkan ke halaman yang benar
    const map = { mahasiswa: '/mahasiswa.html', dosen: '/dosen.html', admin: '/admin.html' };
    window.location.href = map[user.role] || '/index.html';
    return false;
  }

  return true;
}

// ─── UTILITY ─────────────────────────────────────────────────────────────────

function gradeLabel(nilai) {
  if (nilai >= 85) return { label: 'A', cls: 'text-emerald-600 font-semibold' };
  if (nilai >= 75) return { label: 'B', cls: 'text-blue-600 font-semibold' };
  if (nilai >= 65) return { label: 'C', cls: 'text-yellow-600 font-semibold' };
  if (nilai >= 55) return { label: 'D', cls: 'text-orange-500 font-semibold' };
  return { label: 'E', cls: 'text-red-600 font-semibold' };
}

function formatDate(iso) {
  if (!iso) return '-';
  return new Date(iso).toLocaleString('id-ID', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

function showToast(message, type = 'success') {
  const colors = {
    success: 'bg-emerald-500',
    error:   'bg-red-500',
    info:    'bg-blue-500',
    warning: 'bg-amber-500'
  };
  const toast = document.createElement('div');
  toast.className = `fixed top-5 right-5 z-50 px-5 py-3 rounded-lg text-white text-sm shadow-lg transition-all duration-300 ${colors[type] || colors.info}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 3000);
}
