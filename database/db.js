'use strict';

/**
 * db.js — koneksi SQLite menggunakan better-sqlite3 (native binding).
 *
 * better-sqlite3 bekerja secara synchronous dan langsung ke file, sehingga
 * tidak perlu manual persist/reload seperti sql.js. WAL mode diaktifkan
 * untuk mendukung akses multi-process (gateway, service-nilai,
 * service-transkrip) secara konkuren — banyak reader, satu writer pada
 * satu waktu, dengan busy_timeout sebagai fallback.
 *
 * Interface kompatibel dengan kode yang ada:
 *   db.prepare(sql).run(...params) / .get(...params) / .all(...params)
 *   db.exec(sql)
 */

const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = path.join(__dirname, 'sistem_nilai.db');

let _db = null; // better-sqlite3 Database instance (singleton)

// ─── INISIALISASI ─────────────────────────────────────────────────────────────

/**
 * Inisialisasi database (idempotent — aman dipanggil berkali-kali).
 * Membuka koneksi ke file SQLite, mengaktifkan WAL mode, dan
 * menjalankan schema + immutable triggers jika belum ada.
 *
 * @returns {Database} instance better-sqlite3
 */
function initDb() {
  if (_db) return _db;

  _db = new Database(DB_PATH);

  // WAL mode: mengizinkan multiple process read/write ke file yang sama
  _db.pragma('journal_mode = WAL');
  _db.pragma('synchronous = NORMAL');
  _db.pragma('foreign_keys = ON');
  _db.pragma('busy_timeout = 5000'); // tunggu 5 detik jika database locked

  _runSchema();
  return _db;
}

// ─── SCHEMA ───────────────────────────────────────────────────────────────────

function _runSchema() {
  _db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL UNIQUE,
      password_hash TEXT    NOT NULL,
      role          TEXT    NOT NULL,
      nama          TEXT    NOT NULL,
      nim           TEXT    UNIQUE
    );

    CREATE TABLE IF NOT EXISTS devices (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id   INTEGER NOT NULL REFERENCES users(id),
      device_id TEXT    NOT NULL,
      UNIQUE(user_id, device_id)
    );

    CREATE TABLE IF NOT EXISTS kelas (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      nama_kelas TEXT    NOT NULL,
      dosen_id   INTEGER NOT NULL REFERENCES users(id),
      is_final   INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS nilai (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
      kelas_id     INTEGER NOT NULL REFERENCES kelas(id),
      nilai        INTEGER NOT NULL DEFAULT 0,
      is_final     INTEGER NOT NULL DEFAULT 0,
      UNIQUE(mahasiswa_id, kelas_id)
    );

    CREATE TABLE IF NOT EXISTS transkrip (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
      kelas_id     INTEGER NOT NULL REFERENCES kelas(id),
      nilai        INTEGER NOT NULL,
      synced_at    TEXT    NOT NULL,
      UNIQUE(mahasiswa_id, kelas_id)
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id),
      token_hash TEXT    NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL,
      revoked    INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS token_blacklist (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      jti        TEXT    NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT    NOT NULL,
      subject   TEXT    NOT NULL,
      role      TEXT,
      method    TEXT    NOT NULL,
      endpoint  TEXT    NOT NULL,
      device_id TEXT,
      result    TEXT    NOT NULL,
      reason    TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_trail (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp    TEXT    NOT NULL,
      action       TEXT    NOT NULL,
      actor        TEXT    NOT NULL,
      actor_role   TEXT    NOT NULL,
      device_id    TEXT,
      target_table TEXT,
      target_id    INTEGER,
      old_value    TEXT,
      new_value    TEXT,
      meta         TEXT
    );

    -- ─── IMMUTABLE TRIGGERS ─────────────────────────────────────────────────
    CREATE TRIGGER IF NOT EXISTS protect_audit_log_delete
      BEFORE DELETE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log bersifat immutable'); END;

    CREATE TRIGGER IF NOT EXISTS protect_audit_log_update
      BEFORE UPDATE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log bersifat immutable'); END;

    CREATE TRIGGER IF NOT EXISTS protect_audit_trail_delete
      BEFORE DELETE ON audit_trail
      BEGIN SELECT RAISE(ABORT, 'audit_trail bersifat immutable'); END;

    CREATE TRIGGER IF NOT EXISTS protect_audit_trail_update
      BEFORE UPDATE ON audit_trail
      BEGIN SELECT RAISE(ABORT, 'audit_trail bersifat immutable'); END;
  `);
}

// ─── CLEANUP ──────────────────────────────────────────────────────────────────

function cleanupExpiredTokens() {
  const now = Date.now();
  _db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?').run(now);
  _db.prepare('DELETE FROM token_blacklist WHERE expires_at < ?').run(now);
  console.log('[DB] Cleanup expired tokens selesai.');
}

// ─── PUBLIC API ───────────────────────────────────────────────────────────────

/**
 * Mengembalikan instance better-sqlite3 Database.
 * Method tersedia: prepare(sql).run/.get/.all, exec(sql), pragma(str).
 */
function getDb() {
  if (!_db) throw new Error('DB belum diinisialisasi. Panggil initDb() terlebih dahulu.');
  return _db;
}

module.exports = { initDb, getDb, cleanupExpiredTokens };
