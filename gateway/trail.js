'use strict';

/**
 * trail.js — mencatat mutasi data ke tabel audit_trail.
 *
 * Dipanggil oleh:
 *   - gateway/index.js: untuk aksi LOGIN, LOGOUT, TOKEN_SERVICE_ISSUED
 *   - POST /internal/trail: dari Service Nilai & Service Transkrip setelah mutasi data
 *
 * Enum action:
 *   LOGIN | LOGOUT | TOKEN_SERVICE_ISSUED
 *   UPDATE_NILAI | FINALISASI_KELAS | SYNC_TRANSKRIP
 */

const { getDb } = require('../database/db');

/**
 * @param {object} entry
 * @param {string} entry.action        - enum action (lihat atas)
 * @param {string} entry.actor         - username yang melakukan aksi
 * @param {string} entry.actor_role    - role actor
 * @param {string|null} entry.device_id
 * @param {string|null} entry.target_table
 * @param {number|null} entry.target_id
 * @param {object|null} entry.old_value - akan di-JSON.stringify
 * @param {object|null} entry.new_value - akan di-JSON.stringify
 * @param {object|null} entry.meta      - akan di-JSON.stringify
 */
function writeTrail(entry) {
  try {
    const db = getDb();
    db.prepare(`
      INSERT INTO audit_trail
        (timestamp, action, actor, actor_role, device_id,
         target_table, target_id, old_value, new_value, meta)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      new Date().toISOString(),
      entry.action,
      entry.actor       || 'unknown',
      entry.actor_role  || 'unknown',
      entry.device_id   || null,
      entry.target_table || null,
      entry.target_id   ?? null,
      entry.old_value   != null ? JSON.stringify(entry.old_value) : null,
      entry.new_value   != null ? JSON.stringify(entry.new_value) : null,
      entry.meta        != null ? JSON.stringify(entry.meta)      : null
    );
  } catch (err) {
    console.error('[TRAIL] Gagal menulis audit_trail:', err.message);
  }
}

module.exports = { writeTrail };
