'use strict';

/**
 * policy.js — Policy Engine (PE) / Policy Administrator (PA)
 * 
 * Menerima request context dan mengembalikan { allow: boolean, reason: string }
 * 
 * Dipanggil oleh gateway/index.js untuk setiap request non-auth.
 * Membaca database untuk kepemilikan data (kelas diampu, NIM mahasiswa, dll).
 */

const { getDb } = require('../database/db');

/**
 * Evaluasi kebijakan akses.
 *
 * @param {object} ctx
 * @param {object}      ctx.decoded    - JWT payload yang sudah diverifikasi
 * @param {string}      ctx.method     - HTTP method
 * @param {string}      ctx.path       - request path (misal /nilai, /transkrip/2021001)
 * @param {object}      ctx.params     - route params yang sudah di-parse
 * @param {string|null} ctx.deviceId   - header X-Device-ID
 * @returns {{ allow: boolean, reason: string }}
 */
function evaluate(ctx) {
  const { decoded, method, path, params, deviceId } = ctx;
  const { role, sub: userId, device_id: tokenDeviceId, jti } = decoded;

  const db = getDb();

  // ─── 1. CEK TOKEN BLACKLIST ────────────────────────────────────────────────
  if (jti) {
    const blacklisted = db.prepare(
      'SELECT 1 FROM token_blacklist WHERE jti = ? AND expires_at > ?'
    ).get(jti, Date.now());
    if (blacklisted) {
      return { allow: false, reason: 'Token telah dicabut (logout)' };
    }
  }

  // ─── 2. TOKEN BINDING — hanya untuk user, bukan token service ─────────────
  if (role !== 'service') {
    if (!deviceId) {
      return { allow: false, reason: 'Header X-Device-ID wajib disertakan' };
    }

    // Cocokkan device_id di token dengan header yang dikirim
    if (tokenDeviceId && tokenDeviceId !== deviceId) {
      return { allow: false, reason: 'Token tidak valid untuk device ini' };
    }

    // Pastikan device terdaftar di DB untuk user ini
    const device = db.prepare(
      'SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'
    ).get(userId, deviceId);
    if (!device) {
      return { allow: false, reason: 'Device tidak terdaftar untuk user ini' };
    }
  }

  // ─── 3. KEBIJAKAN PER ENDPOINT ────────────────────────────────────────────

  // GET /nilai
  if (method === 'GET' && path === '/nilai') {
    if (role === 'mahasiswa') {
      return { allow: true, reason: 'Mahasiswa mengakses nilai miliknya sendiri' };
    }
    if (role === 'dosen') {
      return { allow: true, reason: 'Dosen mengakses nilai kelas yang diampunya' };
    }
    return { allow: false, reason: `Role '${role}' tidak diizinkan mengakses /nilai` };
  }

  // PUT /nilai/:id
  if (method === 'PUT' && params.nilaiId) {
    if (role !== 'dosen') {
      return { allow: false, reason: 'Hanya dosen yang dapat mengubah nilai' };
    }

    // Cek jam akses
    const jamCheck = _cekJamAkses();
    if (!jamCheck.ok) return { allow: false, reason: jamCheck.reason };

    // Cek nilai exists + kelas diampu + belum final
    const nilaiRow = db.prepare(`
      SELECT n.id, n.is_final, k.dosen_id, k.is_final AS kelas_final
      FROM nilai n
      JOIN kelas k ON k.id = n.kelas_id
      WHERE n.id = ?
    `).get(params.nilaiId);

    if (!nilaiRow) {
      return { allow: false, reason: 'Data nilai tidak ditemukan' };
    }
    if (nilaiRow.dosen_id !== userId) {
      return { allow: false, reason: 'Dosen tidak mengampu kelas tersebut' };
    }
    if (nilaiRow.is_final === 1 || nilaiRow.kelas_final === 1) {
      return { allow: false, reason: 'Nilai sudah difinalisasi, tidak dapat diubah' };
    }

    return { allow: true, reason: 'Dosen mengubah nilai pada kelas ampuannya' };
  }

  // POST /kelas/:id/finalisasi
  if (method === 'POST' && params.kelasId && path.endsWith('/finalisasi')) {
    if (role !== 'dosen') {
      return { allow: false, reason: 'Hanya dosen yang dapat memfinalisasi kelas' };
    }

    const jamCheck = _cekJamAkses();
    if (!jamCheck.ok) return { allow: false, reason: jamCheck.reason };

    const kelas = db.prepare('SELECT id, dosen_id, is_final, nama_kelas FROM kelas WHERE id = ?')
      .get(params.kelasId);

    if (!kelas) {
      return { allow: false, reason: 'Kelas tidak ditemukan' };
    }
    if (kelas.dosen_id !== userId) {
      return { allow: false, reason: 'Dosen tidak mengampu kelas tersebut' };
    }
    if (kelas.is_final === 1) {
      return { allow: false, reason: 'Kelas sudah pernah difinalisasi' };
    }

    return {
      allow: true,
      reason: `Dosen memfinalisasi kelas '${kelas.nama_kelas}' pada ${new Date().toISOString()}`
    };
  }

  // GET /transkrip/:nim
  if (method === 'GET' && params.nim) {
    if (role === 'mahasiswa') {
      const user = db.prepare('SELECT nim FROM users WHERE id = ?').get(userId);
      if (!user || user.nim !== params.nim) {
        return { allow: false, reason: 'Mahasiswa mencoba mengakses transkrip milik NIM lain' };
      }
      return { allow: true, reason: 'Mahasiswa mengakses transkrip miliknya sendiri' };
    }
    if (role === 'admin') {
      // Ambil username admin dari DB untuk audit
      const admin = db.prepare('SELECT username FROM users WHERE id = ?').get(userId);
      return {
        allow: true,
        reason: `Admin '${admin ? admin.username : userId}' mengakses transkrip mahasiswa NIM ${params.nim}`
      };
    }
    return { allow: false, reason: `Role '${role}' tidak diizinkan mengakses transkrip` };
  }

  // POST /transkrip/sinkron
  if (method === 'POST' && path === '/transkrip/sinkron') {
    if (role !== 'service') {
      return {
        allow: false,
        reason: 'Endpoint ini hanya dapat diakses oleh token service, token user ditolak'
      };
    }
    return { allow: true, reason: 'Token service valid, sinkronisasi transkrip diizinkan' };
  }

  // GET /admin/audit-log
  if (method === 'GET' && path === '/admin/audit-log') {
    if (role !== 'admin') {
      return { allow: false, reason: 'Hanya admin yang dapat mengakses audit log' };
    }
    return { allow: true, reason: 'Admin mengakses audit log sistem' };
  }

  // GET /admin/audit-trail
  if (method === 'GET' && path === '/admin/audit-trail') {
    if (role !== 'admin') {
      return { allow: false, reason: 'Hanya admin yang dapat mengakses audit trail' };
    }
    return { allow: true, reason: 'Admin mengakses audit trail sistem' };
  }

  // Endpoint tidak dikenal
  return { allow: false, reason: `Endpoint '${method} ${path}' tidak dikenal` };
}

// ─── HELPER: CEK JAM AKSES ────────────────────────────────────────────────────

function _cekJamAkses() {
  const start = parseInt(process.env.ACCESS_HOUR_START ?? '7',  10);
  const end   = parseInt(process.env.ACCESS_HOUR_END   ?? '21', 10);
  const now   = new Date();
  const hour  = now.getHours();

  if (hour < start || hour >= end) {
    return {
      ok: false,
      reason: `Akses di luar jam yang ditentukan (${String(start).padStart(2,'0')}:00–${String(end).padStart(2,'0')}:00)`
    };
  }
  return { ok: true };
}

/**
 * Parse params dari path aktual.
 * Dipanggil gateway/index.js sebelum memanggil evaluate().
 *
 * @param {string} method
 * @param {string} path
 * @returns {{ nilaiId?: number, kelasId?: number, nim?: string }}
 */
function parseParams(method, path) {
  const params = {};

  // PUT /nilai/:id
  const nilaiMatch = path.match(/^\/nilai\/(\d+)$/);
  if (nilaiMatch) params.nilaiId = parseInt(nilaiMatch[1], 10);

  // POST /kelas/:id/finalisasi
  const finMatch = path.match(/^\/kelas\/(\d+)\/finalisasi$/);
  if (finMatch) params.kelasId = parseInt(finMatch[1], 10);

  // GET /transkrip/:nim
  const transkripMatch = path.match(/^\/transkrip\/([^/]+)$/);
  if (transkripMatch && transkripMatch[1] !== 'sinkron') {
    params.nim = transkripMatch[1];
  }

  return params;
}

module.exports = { evaluate, parseParams };
