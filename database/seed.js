'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const bcrypt   = require('bcryptjs');
const { initDb, getDb } = require('./db');

async function seed() {
  await initDb();
  const db = getDb();

  console.log('[SEED] Memulai seeding...');

  // ─── BERSIHKAN DATA LAMA ────────────────────────────────────────────────────
  // Drop immutable triggers dulu agar bisa DELETE dari audit tables
  db.exec('DROP TRIGGER IF EXISTS protect_audit_log_delete');
  db.exec('DROP TRIGGER IF EXISTS protect_audit_log_update');
  db.exec('DROP TRIGGER IF EXISTS protect_audit_trail_delete');
  db.exec('DROP TRIGGER IF EXISTS protect_audit_trail_update');

  // Hapus dalam urutan yang aman (child sebelum parent)
  db.exec('DELETE FROM transkrip');
  db.exec('DELETE FROM audit_trail');
  db.exec('DELETE FROM audit_log');
  db.exec('DELETE FROM token_blacklist');
  db.exec('DELETE FROM refresh_tokens');
  db.exec('DELETE FROM nilai');
  db.exec('DELETE FROM devices');
  db.exec('DELETE FROM kelas');
  db.exec('DELETE FROM users');

  // Reset autoincrement
  db.exec("DELETE FROM sqlite_sequence WHERE name IN ('users','devices','kelas','nilai','transkrip','refresh_tokens','token_blacklist','audit_log','audit_trail')");

  // ─── USERS ──────────────────────────────────────────────────────────────────
  const users = [
    { username: 'admin1',  password: 'admin123', role: 'admin',     nama: 'Administrator',  nim: null },
    { username: 'dosen1',  password: 'dosen123', role: 'dosen',     nama: 'Dr. Andi Wijaya', nim: null },
    { username: 'dosen2',  password: 'dosen456', role: 'dosen',     nama: 'Dr. Siti Rahayu', nim: null },
    { username: 'mhs1',    password: 'mhs123',   role: 'mahasiswa', nama: 'Budi Santoso',    nim: '2021001' },
    { username: 'mhs2',    password: 'mhs456',   role: 'mahasiswa', nama: 'Citra Dewi',      nim: '2021002' },
    { username: 'mhs3',    password: 'mhs789',   role: 'mahasiswa', nama: 'Dian Pratama',    nim: '2021003' },
  ];

  const userIds = {};
  for (const u of users) {
    const hash = bcrypt.hashSync(u.password, 10);
    db.prepare(
      'INSERT INTO users (username, password_hash, role, nama, nim) VALUES (?, ?, ?, ?, ?)'
    ).run(u.username, hash, u.role, u.nama, u.nim);

    const row = db.prepare('SELECT id FROM users WHERE username = ?').get(u.username);
    userIds[u.username] = row.id;
    console.log(`  [USER] ${u.role.padEnd(10)} ${u.username} (id=${row.id})`);
  }

  // ─── DEVICES ────────────────────────────────────────────────────────────────
  const devices = [
    { username: 'admin1', device_id: 'device-admin-001' },
    { username: 'dosen1', device_id: 'device-dosen-001' },
    { username: 'dosen2', device_id: 'device-dosen-002' },
    { username: 'mhs1',   device_id: 'device-mhs-001'   },
    { username: 'mhs2',   device_id: 'device-mhs-002'   },
    { username: 'mhs3',   device_id: 'device-mhs-003'   },
  ];

  for (const d of devices) {
    db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?, ?)').run(
      userIds[d.username], d.device_id
    );
    console.log(`  [DEV]  ${d.username} → ${d.device_id}`);
  }

  // ─── KELAS ──────────────────────────────────────────────────────────────────
  const kelasData = [
    { nama_kelas: 'Pemrograman Web',      dosen: 'dosen1' },
    { nama_kelas: 'Keamanan Informasi',   dosen: 'dosen2' },
  ];

  const kelasIds = {};
  for (const k of kelasData) {
    db.prepare('INSERT INTO kelas (nama_kelas, dosen_id, is_final) VALUES (?, ?, 0)').run(
      k.nama_kelas, userIds[k.dosen]
    );
    const row = db.prepare('SELECT id FROM kelas WHERE nama_kelas = ?').get(k.nama_kelas);
    kelasIds[k.nama_kelas] = row.id;
    console.log(`  [KELAS] "${k.nama_kelas}" diampu ${k.dosen} (id=${row.id})`);
  }

  // ─── NILAI AWAL ─────────────────────────────────────────────────────────────
  const mahasiswaList = ['mhs1', 'mhs2', 'mhs3'];
  const nilaiAwal = {
    // [username_mhs][nama_kelas] = nilai
    mhs1: { 'Pemrograman Web': 72, 'Keamanan Informasi': 68 },
    mhs2: { 'Pemrograman Web': 85, 'Keamanan Informasi': 78 },
    mhs3: { 'Pemrograman Web': 60, 'Keamanan Informasi': 91 },
  };

  for (const mhs of mahasiswaList) {
    for (const [namaKelas, kelasId] of Object.entries(kelasIds)) {
      const n = nilaiAwal[mhs][namaKelas];
      db.prepare(
        'INSERT INTO nilai (mahasiswa_id, kelas_id, nilai, is_final) VALUES (?, ?, ?, 0)'
      ).run(userIds[mhs], kelasId, n);
      console.log(`  [NILAI] ${mhs} / ${namaKelas} = ${n}`);
    }
  }

  // ─── RECREATE IMMUTABLE TRIGGERS ─────────────────────────────────────────────
  db.exec(`
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
  console.log('  [TRIGGERS] Immutable triggers direcreate');

  console.log('\n[SEED] Selesai!');
  console.log('\n═══════════════════════════════════════════════════');
  console.log(' AKUN & DEVICE ID DATA AWAL');
  console.log('═══════════════════════════════════════════════════');
  console.log(' Username  │ Password  │ Role       │ Device ID');
  console.log('───────────┼───────────┼────────────┼─────────────────────');
  console.log(' admin1    │ admin123  │ admin      │ device-admin-001');
  console.log(' dosen1    │ dosen123  │ dosen      │ device-dosen-001');
  console.log(' dosen2    │ dosen456  │ dosen      │ device-dosen-002');
  console.log(' mhs1      │ mhs123    │ mahasiswa  │ device-mhs-001');
  console.log(' mhs2      │ mhs456    │ mahasiswa  │ device-mhs-002');
  console.log(' mhs3      │ mhs789    │ mahasiswa  │ device-mhs-003');
  console.log('═══════════════════════════════════════════════════\n');
}

seed().catch(e => {
  console.error('[SEED] ERROR:', e);
  process.exit(1);
});
