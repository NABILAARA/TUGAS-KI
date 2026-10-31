'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const express = require('express');
const jwt     = require('jsonwebtoken');
const http    = require('http');

const { initDb, getDb } = require('../database/db');

const PORT            = parseInt(process.env.PORT_TRANSKRIP || '3002', 10);
const GATEWAY_SECRET  = process.env.GATEWAY_SECRET;
const INTERNAL_SECRET = process.env.INTERNAL_SECRET;
const JWT_SECRET      = process.env.JWT_SECRET;
const PORT_GATEWAY    = parseInt(process.env.PORT_GATEWAY || '3000', 10);

const app = express();
app.use(express.json());

// ─── MIDDLEWARE: Verifikasi Gateway Secret + JWT ───────────────────────────────
function verifyGatewayAndToken(req, res, next) {
  if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) {
    return res.status(403).json({ success: false, error: 'Akses langsung ke service tidak diizinkan' });
  }

  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Token tidak ditemukan' });
  }
  const token = auth.slice(7);
  try {
    req.decoded = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ success: false, error: 'Token tidak valid atau sudah kedaluwarsa' });
  }

  next();
}

// ─── Helper: kirim trail ke gateway ──────────────────────────────────────────
function sendTrail(entry) {
  const body = JSON.stringify(entry);
  const opts = {
    hostname: '127.0.0.1', port: PORT_GATEWAY,
    path: '/internal/trail', method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
      'X-Internal-Secret': INTERNAL_SECRET
    }
  };
  const r = http.request(opts);
  r.on('error', e => console.error('[TRAIL] Gagal kirim trail:', e.message));
  r.write(body);
  r.end();
}

// ─── GET /transkrip/:nim ──────────────────────────────────────────────────────
app.get('/transkrip/:nim', verifyGatewayAndToken, (req, res) => {
  const db = getDb();
  const { role, sub: userId } = req.decoded;
  const { nim } = req.params;

  // Policy sudah diverifikasi di gateway, tapi service juga verifikasi ulang
  if (role === 'mahasiswa') {
    const user = db.prepare('SELECT nim FROM users WHERE id = ?').get(userId);
    if (!user || user.nim !== nim) {
      return res.status(403).json({ success: false, error: 'Tidak diizinkan mengakses transkrip ini' });
    }
  } else if (role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Role tidak diizinkan' });
  }

  // Cari mahasiswa
  const mahasiswa = db.prepare('SELECT id, nama, nim, username FROM users WHERE nim = ? AND role = ?').get(nim, 'mahasiswa');
  if (!mahasiswa) {
    return res.status(404).json({ success: false, error: `Mahasiswa dengan NIM ${nim} tidak ditemukan` });
  }

  const rows = db.prepare(`
    SELECT t.id, t.nilai, t.synced_at,
           k.nama_kelas, k.id AS kelas_id
    FROM transkrip t
    JOIN kelas k ON k.id = t.kelas_id
    WHERE t.mahasiswa_id = ?
    ORDER BY k.nama_kelas
  `).all(mahasiswa.id);

  return res.json({
    success: true,
    data: {
      mahasiswa: { nama: mahasiswa.nama, nim: mahasiswa.nim },
      transkrip: rows
    }
  });
});

// ─── POST /transkrip/sinkron ──────────────────────────────────────────────────
app.post('/transkrip/sinkron', verifyGatewayAndToken, (req, res) => {
  const db = getDb();
  const { role } = req.decoded;

  // Hanya token service yang boleh
  if (role !== 'service') {
    return res.status(403).json({ success: false, error: 'Endpoint ini hanya dapat diakses oleh token service' });
  }

  const { kelas_id } = req.body;
  if (!kelas_id) {
    return res.status(400).json({ success: false, error: 'kelas_id wajib diisi' });
  }

  const kelas = db.prepare('SELECT * FROM kelas WHERE id = ? AND is_final = 1').get(kelas_id);
  if (!kelas) {
    return res.status(400).json({ success: false, error: 'Kelas tidak ditemukan atau belum difinalisasi' });
  }

  // Ambil semua nilai final di kelas ini
  const nilaiList = db.prepare(`
    SELECT n.mahasiswa_id, n.nilai, n.kelas_id,
           u.nim, u.nama
    FROM nilai n
    JOIN users u ON u.id = n.mahasiswa_id
    WHERE n.kelas_id = ? AND n.is_final = 1
  `).all(kelas_id);

  if (nilaiList.length === 0) {
    return res.status(400).json({ success: false, error: 'Tidak ada nilai final untuk disinkronkan' });
  }

  const syncedAt = new Date().toISOString();
  const nimTerdampak = [];

  for (const n of nilaiList) {
    // Upsert transkrip
    const existing = db.prepare(
      'SELECT id FROM transkrip WHERE mahasiswa_id = ? AND kelas_id = ?'
    ).get(n.mahasiswa_id, kelas_id);

    if (existing) {
      db.prepare('UPDATE transkrip SET nilai = ?, synced_at = ? WHERE mahasiswa_id = ? AND kelas_id = ?')
        .run(n.nilai, syncedAt, n.mahasiswa_id, kelas_id);
    } else {
      db.prepare('INSERT INTO transkrip (mahasiswa_id, kelas_id, nilai, synced_at) VALUES (?, ?, ?, ?)')
        .run(n.mahasiswa_id, kelas_id, n.nilai, syncedAt);
    }
    nimTerdampak.push(n.nim);
  }

  // Kirim audit trail
  sendTrail({
    action: 'SYNC_TRANSKRIP',
    actor: 'service-nilai',
    actor_role: 'service',
    device_id: null,
    target_table: 'transkrip',
    target_id: null,
    old_value: null,
    new_value: null,
    meta: {
      kelas_id,
      nama_kelas: kelas.nama_kelas,
      jumlah_record_disinkron: nilaiList.length,
      nim_terdampak: nimTerdampak
    }
  });

  return res.json({
    success: true,
    data: {
      kelas_id,
      nama_kelas: kelas.nama_kelas,
      jumlah_disinkron: nilaiList.length,
      synced_at: syncedAt,
      nim_terdampak: nimTerdampak
    }
  });
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ success: true, data: { service: 'transkrip', status: 'ok', ts: new Date().toISOString() } });
});

// ─── START ────────────────────────────────────────────────────────────────────
(async () => {
  await initDb();
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[SERVICE-TRANSKRIP] Berjalan di http://127.0.0.1:${PORT}`);
    console.log(`[SERVICE-TRANSKRIP] Hanya menerima request dari gateway (via X-Gateway-Secret)`);
  });
})();
