'use strict';

/**
 * audit.js — mencatat setiap keputusan akses gateway ke tabel audit_log.
 * Dipanggil oleh gateway/index.js setelah setiap request diproses.
 */

const { getDb } = require('../database/db');

/**
 * @param {object} entry
 * @param {string} entry.subject   - username atau 'service-nilai'
 * @param {string} entry.role      - role user (mahasiswa/dosen/admin/service)
 * @param {string} entry.method    - HTTP method
 * @param {string} entry.endpoint  - path request
 * @param {string|null} entry.device_id - X-Device-ID header (null untuk token service)
 * @param {'allow'|'deny'} entry.result
 * @param {string} entry.reason    - alasan keputusan policy engine
 */
function writeLog(entry) {
  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO audit_log (timestamp, subject, role, method, endpoint, device_id, result, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      new Date().toISOString(),
      entry.subject   || 'unknown',
      entry.role      || null,
      entry.method    || '-',
      entry.endpoint  || '-',
      entry.device_id || null,
      entry.result,
      entry.reason
    );
  } catch (err) {
    // Jangan sampai error audit merusak request utama
    console.error('[AUDIT] Gagal menulis audit_log:', err.message);
  }
}

module.exports = { writeLog };
