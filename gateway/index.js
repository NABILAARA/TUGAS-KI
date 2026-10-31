'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const express    = require('express');
const cors       = require('cors');
const crypto     = require('crypto');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const rateLimit  = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');

const { initDb, getDb, cleanupExpiredTokens } = require('../database/db');
const { writeLog }   = require('./audit');
const { writeTrail } = require('./trail');
const { evaluate, parseParams } = require('./policy');

// ─── STARTUP VALIDATION ───────────────────────────────────────────────────────
const REQUIRED_SECRETS = ['JWT_SECRET', 'GATEWAY_SECRET', 'INTERNAL_SECRET', 'SERVICE_CLIENT_SECRET'];
for (const key of REQUIRED_SECRETS) {
  if (!process.env[key] || process.env[key].length < 32) {
    console.error(`FATAL: ${key} tidak ada atau terlalu pendek (min 32 karakter)`);
    process.exit(1);
  }
}

const PORT_GATEWAY   = parseInt(process.env.PORT_GATEWAY   || '3000', 10);
const PORT_NILAI     = parseInt(process.env.PORT_NILAI     || '3001', 10);
const PORT_TRANSKRIP = parseInt(process.env.PORT_TRANSKRIP || '3002', 10);
const JWT_SECRET         = process.env.JWT_SECRET;
const GATEWAY_SECRET     = process.env.GATEWAY_SECRET;
const INTERNAL_SECRET    = process.env.INTERNAL_SECRET;
const SERVICE_CLIENT_ID  = process.env.SERVICE_CLIENT_ID;
const SERVICE_CLIENT_SECRET = process.env.SERVICE_CLIENT_SECRET;

// ─── HELPERS ──────────────────────────────────────────────────────────────────

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function issueAccessToken(payload) {
  const jti = crypto.randomUUID();
  return jwt.sign({ ...payload, jti }, JWT_SECRET, { expiresIn: '10m' });
}

function issueRefreshToken() {
  return crypto.randomBytes(40).toString('hex');
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function bearerToken(req) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return null;
  return auth.slice(7);
}

// ─── APP ──────────────────────────────────────────────────────────────────────

const app = express();

app.use(cors());
app.use(express.json());

// Sajikan frontend secara statis
const path = require('path');
app.use(express.static(path.join(__dirname, '../frontend')));

// ─── RATE LIMITER (khusus login) ──────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 menit
  max: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Terlalu banyak percobaan login, coba lagi dalam 1 menit' }
});

// ─── AUTH: POST /auth/login ───────────────────────────────────────────────────
app.post('/auth/login', loginLimiter, async (req, res) => {
  const db = getDb();
  const { username, password } = req.body || {};
  const deviceId = req.headers['x-device-id'] || null;
  const method = 'POST', endpoint = '/auth/login';

  // Cek X-Device-ID
  if (!deviceId) {
    writeLog({ subject: username || 'unknown', role: null, method, endpoint,
               device_id: null, result: 'deny', reason: 'Header X-Device-ID wajib disertakan saat login' });
    return res.status(400).json({ success: false, error: 'Header X-Device-ID wajib disertakan' });
  }

  // Cek kredensial
  if (!username || !password) {
    writeLog({ subject: username || 'unknown', role: null, method, endpoint,
               device_id: deviceId, result: 'deny', reason: 'Username dan password wajib diisi' });
    return res.status(400).json({ success: false, error: 'Username dan password wajib diisi' });
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    writeLog({ subject: username, role: null, method, endpoint,
               device_id: deviceId, result: 'deny', reason: 'Kredensial tidak valid' });
    return res.status(401).json({ success: false, error: 'Username atau password salah' });
  }

  // Cek device terdaftar
  const device = db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?').get(user.id, deviceId);
  if (!device) {
    writeLog({ subject: username, role: user.role, method, endpoint,
               device_id: deviceId, result: 'deny', reason: 'Device tidak terdaftar untuk user ini' });
    return res.status(403).json({ success: false, error: 'Device tidak terdaftar' });
  }

  // Terbitkan token
  const accessToken  = issueAccessToken({ sub: user.id, role: user.role, device_id: deviceId });
  const refreshPlain = issueRefreshToken();
  const expiresAt    = Date.now() + 24 * 60 * 60 * 1000; // 1 hari

  db.prepare('INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked) VALUES (?, ?, ?, 0)')
    .run(user.id, sha256(refreshPlain), expiresAt);

  writeLog({ subject: username, role: user.role, method, endpoint,
             device_id: deviceId, result: 'allow', reason: 'Login berhasil' });

  writeTrail({ action: 'LOGIN', actor: username, actor_role: user.role,
               device_id: deviceId, target_table: 'users', target_id: user.id,
               old_value: null, new_value: null, meta: { ip: req.ip } });

  return res.json({
    success: true,
    data: {
      access_token: accessToken,
      refresh_token: refreshPlain,
      role: user.role,
      nama: user.nama,
      username: user.username
    }
  });
});

// ─── AUTH: POST /auth/refresh ─────────────────────────────────────────────────
app.post('/auth/refresh', (req, res) => {
  const db = getDb();
  const { refresh_token } = req.body || {};
  const endpoint = '/auth/refresh';

  if (!refresh_token) {
    return res.status(400).json({ success: false, error: 'refresh_token wajib diisi' });
  }

  const row = db.prepare(
    'SELECT rt.*, u.role, u.username, u.id AS uid FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id WHERE rt.token_hash = ? AND rt.revoked = 0 AND rt.expires_at > ?'
  ).get(sha256(refresh_token), Date.now());

  if (!row) {
    writeLog({ subject: 'unknown', role: null, method: 'POST', endpoint,
               device_id: null, result: 'deny', reason: 'Refresh token tidak valid atau telah dicabut' });
    return res.status(401).json({ success: false, error: 'Refresh token tidak valid atau sudah kedaluwarsa' });
  }

  // Ambil device_id dari token lama jika ada
  const deviceId = req.headers['x-device-id'] || null;
  const newAccess = issueAccessToken({ sub: row.uid, role: row.role, device_id: deviceId });

  writeLog({ subject: row.username, role: row.role, method: 'POST', endpoint,
             device_id: deviceId, result: 'allow', reason: 'Refresh token valid, access token diperbarui' });

  return res.json({ success: true, data: { access_token: newAccess } });
});

// ─── AUTH: POST /auth/logout ──────────────────────────────────────────────────
app.post('/auth/logout', (req, res) => {
  const db = getDb();
  const { refresh_token } = req.body || {};
  const accessToken = bearerToken(req);
  const endpoint = '/auth/logout';

  let subject = 'unknown', role = null, deviceId = req.headers['x-device-id'] || null;

  // Blacklist access token (jti)
  if (accessToken) {
    const decoded = verifyToken(accessToken);
    if (decoded) {
      subject = String(decoded.sub);
      role = decoded.role;
      deviceId = decoded.device_id || deviceId;
      if (decoded.jti) {
        db.prepare('INSERT OR IGNORE INTO token_blacklist (jti, expires_at) VALUES (?, ?)')
          .run(decoded.jti, decoded.exp ? decoded.exp * 1000 : Date.now() + 10 * 60 * 1000);
      }
    }
  }

  // Cabut refresh token
  if (refresh_token) {
    const row = db.prepare('SELECT rt.*, u.username, u.role FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id WHERE rt.token_hash = ?')
      .get(sha256(refresh_token));
    if (row) {
      db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?').run(sha256(refresh_token));
      subject = row.username;
      role = row.role;
    }
  }

  writeLog({ subject, role, method: 'POST', endpoint,
             device_id: deviceId, result: 'allow', reason: 'Refresh token dicabut, sesi diakhiri' });

  writeTrail({ action: 'LOGOUT', actor: subject, actor_role: role || 'unknown',
               device_id: deviceId, target_table: 'refresh_tokens', target_id: null,
               old_value: null, new_value: null, meta: null });

  return res.json({ success: true, data: { message: 'Logout berhasil' } });
});

// ─── AUTH: POST /auth/service ─────────────────────────────────────────────────
app.post('/auth/service', (req, res) => {
  const db = getDb();
  const { client_id, client_secret } = req.body || {};
  const endpoint = '/auth/service';

  if (client_id !== SERVICE_CLIENT_ID || client_secret !== SERVICE_CLIENT_SECRET) {
    writeLog({ subject: client_id || 'unknown', role: 'service', method: 'POST', endpoint,
               device_id: null, result: 'deny', reason: 'Client ID atau secret tidak valid' });
    return res.status(401).json({ success: false, error: 'Client ID atau secret tidak valid' });
  }

  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: 'service-nilai', role: 'service', jti },
    JWT_SECRET,
    { expiresIn: '5m' }
  );

  writeLog({ subject: client_id, role: 'service', method: 'POST', endpoint,
             device_id: null, result: 'allow', reason: 'Token service diterbitkan' });

  writeTrail({ action: 'TOKEN_SERVICE_ISSUED', actor: client_id, actor_role: 'service',
               device_id: null, target_table: null, target_id: null,
               old_value: null, new_value: null, meta: { client_id } });

  return res.json({ success: true, data: { access_token: token } });
});

// ─── INTERNAL: POST /internal/trail ──────────────────────────────────────────
// Hanya dari localhost + X-Internal-Secret
app.post('/internal/trail', (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress || '';
  const isLocal  = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1';
  const secret   = req.headers['x-internal-secret'];

  if (!isLocal || secret !== INTERNAL_SECRET) {
    return res.status(403).json({ success: false, error: 'Akses ditolak' });
  }

  const entry = req.body;
  if (!entry || !entry.action || !entry.actor) {
    return res.status(400).json({ success: false, error: 'Body tidak valid' });
  }

  writeTrail(entry);
  return res.json({ success: true });
});

// ─── MIDDLEWARE: VERIFIKASI TOKEN & PROXY ─────────────────────────────────────

function authMiddleware(req, res, next) {
  const token = bearerToken(req);
  if (!token) {
    _denyRequest(req, res, 'unknown', null, null, 'Token tidak ditemukan di header Authorization');
    return;
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    _denyRequest(req, res, 'unknown', null, req.headers['x-device-id'], 'Token tidak valid atau sudah kedaluwarsa');
    return;
  }

  req.decoded = decoded;
  next();
}

function policyMiddleware(req, res, next) {
  const decoded  = req.decoded;
  const deviceId = decoded.role === 'service' ? null : (req.headers['x-device-id'] || null);
  // req.originalUrl membawa full path termasuk prefix (/nilai, /kelas, /transkrip)
  const reqPath  = req.originalUrl.split('?')[0];
  const params   = parseParams(req.method, reqPath);

  const result = evaluate({ decoded, method: req.method, path: reqPath, params, deviceId });

  const subject = decoded.role === 'service'
    ? String(decoded.sub)
    : _usernameFromId(decoded.sub);

  writeLog({
    subject,
    role: decoded.role,
    method: req.method,
    endpoint: reqPath,
    device_id: deviceId,
    result: result.allow ? 'allow' : 'deny',
    reason: result.reason
  });

  if (!result.allow) {
    return res.status(403).json({ success: false, error: result.reason });
  }

  next();
}

function _usernameFromId(userId) {
  try {
    const db = getDb();
    const u = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
    return u ? u.username : String(userId);
  } catch { return String(userId); }
}

function _denyRequest(req, res, subject, role, deviceId, reason) {
  writeLog({
    subject, role, method: req.method,
    endpoint: req.path, device_id: deviceId,
    result: 'deny', reason
  });
  return res.status(401).json({ success: false, error: reason });
}

// ─── ADMIN ENDPOINTS (langsung dari DB, tanpa proxy) ─────────────────────────
app.get('/admin/audit-log', authMiddleware, policyMiddleware, (req, res) => {
  const db = getDb();
  const { result: filterResult, limit: lim = 100, offset: off = 0 } = req.query;
  let rows;
  if (filterResult && (filterResult === 'allow' || filterResult === 'deny')) {
    rows = db.prepare(
      'SELECT * FROM audit_log WHERE result = ? ORDER BY id DESC LIMIT ? OFFSET ?'
    ).all(filterResult, parseInt(lim), parseInt(off));
  } else {
    rows = db.prepare(
      'SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?'
    ).all(parseInt(lim), parseInt(off));
  }
  const total = db.prepare('SELECT COUNT(*) AS c FROM audit_log').get().c;
  return res.json({ success: true, data: { rows, total } });
});

app.get('/admin/audit-trail', authMiddleware, policyMiddleware, (req, res) => {
  const db = getDb();
  const { action: filterAction, limit: lim = 100, offset: off = 0 } = req.query;
  let rows;
  if (filterAction) {
    rows = db.prepare(
      'SELECT * FROM audit_trail WHERE action = ? ORDER BY id DESC LIMIT ? OFFSET ?'
    ).all(filterAction, parseInt(lim), parseInt(off));
  } else {
    rows = db.prepare(
      'SELECT * FROM audit_trail ORDER BY id DESC LIMIT ? OFFSET ?'
    ).all(parseInt(lim), parseInt(off));
  }
  const total = db.prepare('SELECT COUNT(*) AS c FROM audit_trail').get().c;
  return res.json({ success: true, data: { rows, total } });
});

// ─── ROUTE PROXY ─────────────────────────────────────────────────────────────
// Catatan: app.use('/nilai', proxy) akan strip '/nilai' dari path sebelum proxy.
// Service sudah listen dengan path penuh (/nilai, /kelas, /transkrip),
// jadi kita gunakan pathRewrite object untuk mengembalikan prefix.
app.use('/nilai',   authMiddleware, policyMiddleware, createProxyMiddleware({
  target: `http://127.0.0.1:${PORT_NILAI}`,
  changeOrigin: false,
  pathRewrite: { '^/': '/nilai/' },
  on: {
    proxyReq(proxyReq, req) {
      proxyReq.setHeader('X-Gateway-Secret', GATEWAY_SECRET);
      if (req.body && Object.keys(req.body).length > 0) {
        const bd = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bd));
        proxyReq.write(bd);
      }
    },
    error(err, req, res) { res.status(502).json({ success: false, error: 'Service Nilai tidak tersedia' }); }
  }
}));

app.use('/kelas',   authMiddleware, policyMiddleware, createProxyMiddleware({
  target: `http://127.0.0.1:${PORT_NILAI}`,
  changeOrigin: false,
  pathRewrite: { '^/': '/kelas/' },
  on: {
    proxyReq(proxyReq, req) {
      proxyReq.setHeader('X-Gateway-Secret', GATEWAY_SECRET);
      if (req.body && Object.keys(req.body).length > 0) {
        const bd = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bd));
        proxyReq.write(bd);
      }
    },
    error(err, req, res) { res.status(502).json({ success: false, error: 'Service Nilai tidak tersedia' }); }
  }
}));

app.use('/transkrip', authMiddleware, policyMiddleware, createProxyMiddleware({
  target: `http://127.0.0.1:${PORT_TRANSKRIP}`,
  changeOrigin: false,
  pathRewrite: { '^/': '/transkrip/' },
  on: {
    proxyReq(proxyReq, req) {
      proxyReq.setHeader('X-Gateway-Secret', GATEWAY_SECRET);
      if (req.body && Object.keys(req.body).length > 0) {
        const bd = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bd));
        proxyReq.write(bd);
      }
    },
    error(err, req, res) { res.status(502).json({ success: false, error: 'Service Transkrip tidak tersedia' }); }
  }
}));

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ success: true, data: { service: 'gateway', status: 'ok', ts: new Date().toISOString() } });
});

// ─── START ────────────────────────────────────────────────────────────────────
(async () => {
  await initDb();
  cleanupExpiredTokens();

  app.listen(PORT_GATEWAY, '0.0.0.0', () => {
    console.log(`[GATEWAY] Berjalan di http://localhost:${PORT_GATEWAY}`);
    console.log(`[GATEWAY] Service Nilai  → http://localhost:${PORT_NILAI}`);
    console.log(`[GATEWAY] Service Transkrip → http://localhost:${PORT_TRANSKRIP}`);
  });
})();
