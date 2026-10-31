'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const express = require('express');
const jwt     = require('jsonwebtoken');
const http    = require('http');

const { initDb, getDb } = require('../database/db');

const PORT           = parseInt(process.env.PORT_NILAI || '3001', 10);
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;
const INTERNAL_SECRET = process.env.INTERNAL_SECRET;
const JWT_SECRET     = process.env.JWT_SECRET;
const PORT_GATEWAY   = parseInt(process.env.PORT_GATEWAY || '3000', 10);
const SERVICE_CLIENT_ID     = process.env.SERVICE_CLIENT_ID;
const SERVICE_CLIENT_SECRET = process.env.SERVICE_CLIENT_SECRET;

const app = express();
app.use(express.json());

// ─── MIDDLEWARE: Verifikasi Gateway Secret + JWT ───────────────────────────────
function verifyGatewayAndToken(req, res, next) {
  // 1. Wajib ada X-Gateway-Secret
  if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) {
    return res.status(403).json({ success: false, error: 'Akses langsung ke service tidak diizinkan' });
  }

  // 2. Verifikasi JWT secara mandiri
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

// ─── Helper: dapatkan token service dari gateway ──────────────────────────────
function getServiceToken() {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ client_id: SERVICE_CLIENT_ID, client_secret: SERVICE_CLIENT_SECRET });
    const opts = {
      hostname: '127.0.0.1', port: PORT_GATEWAY,
      path: '/auth/service', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    };
    const r = http.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          if (parsed.success) resolve(parsed.data.access_token);
          else reject(new Error('Gagal mendapatkan token service: ' + JSON.stringify(parsed)));
        } catch (e) { reject(e); }
      });
    });
    r.on('error', reject);
    r.write(body);
    r.end();
  });
}

// ─── Helper: panggil sinkron transkrip via gateway ────────────────────────────
function sinkronTranskrip(kelasId, serviceToken) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ kelas_id: kelasId });
    const opts = {
      hostname: '127.0.0.1', port: PORT_GATEWAY,
      path: '/transkrip/sinkron', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${serviceToken}`
      }
    };
    const r = http.request(opts, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { resolve(JSON.parse(d)); }
        catch (e) { reject(e); }
      });
    });
    r.on('error', reject);
    r.write(body);
    r.end();
  });
}

// ─── GET /nilai ───────────────────────────────────────────────────────────────
app.get('/nilai', verifyGatewayAndToken, (req, res) => {
  const db = getDb();
  const { role, sub: userId } = req.decoded;

  let rows;

  if (role === 'mahasiswa') {
    // Mahasiswa hanya lihat nilai miliknya
    rows = db.prepare(`
      SELECT n.id, n.nilai, n.is_final,
             k.nama_kelas, k.id AS kelas_id,
             u.nama AS nama_mahasiswa, u.nim
      FROM nilai n
      JOIN kelas k ON k.id = n.kelas_id
      JOIN users u ON u.id = n.mahasiswa_id
      WHERE n.mahasiswa_id = ?
      ORDER BY k.nama_kelas
    `).all(userId);

  } else if (role === 'dosen') {
    // Dosen hanya lihat nilai kelas yang diampunya
    rows = db.prepare(`
      SELECT n.id, n.nilai, n.is_final,
             k.nama_kelas, k.id AS kelas_id, k.is_final AS kelas_final,
             u.nama AS nama_mahasiswa, u.nim
      FROM nilai n
      JOIN kelas k ON k.id = n.kelas_id
      JOIN users u ON u.id = n.mahasiswa_id
      WHERE k.dosen_id = ?
      ORDER BY k.nama_kelas, u.nama
    `).all(userId);

  } else {
    return res.status(403).json({ success: false, error: 'Role tidak diizinkan' });
  }

  return res.json({ success: true, data: { nilai: rows } });
});

// ─── PUT /nilai/:id ───────────────────────────────────────────────────────────
app.put('/nilai/:id', verifyGatewayAndToken, (req, res) => {
  const db = getDb();
  const { role, sub: userId, device_id: deviceId } = req.decoded;
  const nilaiId = parseInt(req.params.id, 10);

  if (role !== 'dosen') {
    return res.status(403).json({ success: false, error: 'Hanya dosen yang dapat mengubah nilai' });
  }

  // Validasi input nilai
  const newNilai = parseInt(req.body.nilai, 10);
  if (isNaN(newNilai) || newNilai < 0 || newNilai > 100) {
    return res.status(400).json({ success: false, error: 'Nilai harus berupa angka antara 0 dan 100' });
  }

  // Ambil data sebelum update untuk audit trail
  const existing = db.prepare(`
    SELECT n.*, k.dosen_id, k.is_final AS kelas_final,
           u.nama AS nama_mahasiswa, u.nim, u2.username AS dosen_username,
           k.nama_kelas
    FROM nilai n
    JOIN kelas k ON k.id = n.kelas_id
    JOIN users u ON u.id = n.mahasiswa_id
    JOIN users u2 ON u2.id = k.dosen_id
    WHERE n.id = ?
  `).get(nilaiId);

  if (!existing) {
    return res.status(404).json({ success: false, error: 'Data nilai tidak ditemukan' });
  }
  if (existing.dosen_id !== userId) {
    return res.status(403).json({ success: false, error: 'Dosen tidak mengampu kelas tersebut' });
  }
  if (existing.is_final === 1 || existing.kelas_final === 1) {
    return res.status(403).json({ success: false, error: 'Nilai sudah difinalisasi, tidak dapat diubah' });
  }

  // Update
  db.prepare('UPDATE nilai SET nilai = ? WHERE id = ?').run(newNilai, nilaiId);

  // Kirim audit trail
  sendTrail({
    action: 'UPDATE_NILAI',
    actor: existing.dosen_username,
    actor_role: 'dosen',
    device_id: deviceId || null,
    target_table: 'nilai',
    target_id: nilaiId,
    old_value: { nilai: existing.nilai, is_final: existing.is_final },
    new_value: { nilai: newNilai, is_final: existing.is_final },
    meta: {
      nama_mahasiswa: existing.nama_mahasiswa,
      nim: existing.nim,
      nama_kelas: existing.nama_kelas
    }
  });

  return res.json({
    success: true,
    data: {
      id: nilaiId,
      nilai: newNilai,
      nama_mahasiswa: existing.nama_mahasiswa,
      nama_kelas: existing.nama_kelas,
      message: 'Nilai berhasil diperbarui'
    }
  });
});

// ─── POST /kelas/:id/finalisasi ───────────────────────────────────────────────
app.post('/kelas/:id/finalisasi', verifyGatewayAndToken, async (req, res) => {
  const db = getDb();
  const { role, sub: userId, device_id: deviceId } = req.decoded;
  const kelasId = parseInt(req.params.id, 10);

  if (role !== 'dosen') {
    return res.status(403).json({ success: false, error: 'Hanya dosen yang dapat memfinalisasi kelas' });
  }

  const kelas = db.prepare(`
    SELECT k.*, u.username AS dosen_username
    FROM kelas k JOIN users u ON u.id = k.dosen_id
    WHERE k.id = ?
  `).get(kelasId);

  if (!kelas) return res.status(404).json({ success: false, error: 'Kelas tidak ditemukan' });
  if (kelas.dosen_id !== userId) return res.status(403).json({ success: false, error: 'Dosen tidak mengampu kelas tersebut' });
  if (kelas.is_final === 1) return res.status(403).json({ success: false, error: 'Kelas sudah pernah difinalisasi' });

  // Set is_final = 1 untuk semua nilai di kelas ini + kelas itu sendiri
  db.prepare('UPDATE nilai SET is_final = 1 WHERE kelas_id = ?').run(kelasId);
  db.prepare('UPDATE kelas SET is_final = 1 WHERE id = ?').run(kelasId);

  const jumlah = db.prepare('SELECT COUNT(*) AS c FROM nilai WHERE kelas_id = ?').get(kelasId).c;

  // Kirim audit trail finalisasi
  sendTrail({
    action: 'FINALISASI_KELAS',
    actor: kelas.dosen_username,
    actor_role: 'dosen',
    device_id: deviceId || null,
    target_table: 'kelas',
    target_id: kelasId,
    old_value: { is_final: 0 },
    new_value: { is_final: 1 },
    meta: { nama_kelas: kelas.nama_kelas, jumlah_mahasiswa_terfinalisasi: jumlah }
  });

  // Sinkron transkrip via gateway menggunakan token service
  try {
    const serviceToken = await getServiceToken();
    const sinkronResult = await sinkronTranskrip(kelasId, serviceToken);
    return res.json({
      success: true,
      data: {
        kelas_id: kelasId,
        nama_kelas: kelas.nama_kelas,
        jumlah_terfinalisasi: jumlah,
        sinkron: sinkronResult
      }
    });
  } catch (e) {
    console.error('[FINALISASI] Sinkron transkrip gagal:', e.message);
    return res.json({
      success: true,
      data: {
        kelas_id: kelasId,
        nama_kelas: kelas.nama_kelas,
        jumlah_terfinalisasi: jumlah,
        sinkron: { success: false, error: 'Sinkron transkrip gagal: ' + e.message }
      }
    });
  }
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ success: true, data: { service: 'nilai', status: 'ok', ts: new Date().toISOString() } });
});

// ─── START ────────────────────────────────────────────────────────────────────
(async () => {
  await initDb();
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[SERVICE-NILAI] Berjalan di http://127.0.0.1:${PORT}`);
    console.log(`[SERVICE-NILAI] Hanya menerima request dari gateway (via X-Gateway-Secret)`);
  });
})();
