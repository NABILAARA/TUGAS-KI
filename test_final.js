'use strict';
require('dotenv').config();
const http = require('http');

function req(method, path, headers = {}, body = null, port = 3000) {
  return new Promise((resolve) => {
    const bs = body ? JSON.stringify(body) : null;
    const r = http.request({
      hostname: '127.0.0.1', port, path, method,
      headers: { 'Content-Type': 'application/json', ...headers, ...(bs ? { 'Content-Length': Buffer.byteLength(bs) } : {}) }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve({ s: res.statusCode, b: JSON.parse(d) }); } catch { resolve({ s: res.statusCode, b: d }); } });
    });
    r.on('error', e => resolve({ s: 0, b: { error: e.message } }));
    if (bs) r.write(bs);
    r.end();
  });
}

let pass = 0, fail = 0;
function check(label, got, expect, extraMsg = '') {
  const ok = got === expect;
  console.log(`  ${ok ? '✓' : '✗'} ${label} → HTTP ${got}${!ok ? ` (expect ${expect})` : ''}${extraMsg ? ' | ' + extraMsg : ''}`);
  ok ? pass++ : fail++;
  return ok;
}

async function run() {
  console.log('\n══════════════════════════════════════════════════');
  console.log('  FINAL VERIFICATION — Sistem Nilai Zero Trust');
  console.log('══════════════════════════════════════════════════\n');

  // ── Health ──────────────────────────────────────────────────────────────────
  console.log('[1] Health checks');
  check('Gateway', (await req('GET', '/health')).s, 200);
  check('Service Nilai (direct)', (await req('GET', '/health', {}, null, 3001)).s, 200);
  check('Service Transkrip (direct)', (await req('GET', '/health', {}, null, 3002)).s, 200);

  // ── Auth ────────────────────────────────────────────────────────────────────
  console.log('\n[2] Autentikasi');
  check('Login tanpa X-Device-ID → 400',
    (await req('POST', '/auth/login', {}, { username: 'mhs1', password: 'mhs123' })).s, 400);
  check('Login device tidak terdaftar → 403',
    (await req('POST', '/auth/login', { 'X-Device-ID': 'device-hacker' }, { username: 'mhs1', password: 'mhs123' })).s, 403);
  check('Login password salah → 401',
    (await req('POST', '/auth/login', { 'X-Device-ID': 'device-mhs-001' }, { username: 'mhs1', password: 'SALAH' })).s, 401);

  const lMhs    = await req('POST', '/auth/login', { 'X-Device-ID': 'device-mhs-001' },    { username: 'mhs1',   password: 'mhs123' });
  const lDosen1 = await req('POST', '/auth/login', { 'X-Device-ID': 'device-dosen-001' },  { username: 'dosen1', password: 'dosen123' });
  const lDosen2 = await req('POST', '/auth/login', { 'X-Device-ID': 'device-dosen-002' },  { username: 'dosen2', password: 'dosen456' });
  const lAdmin  = await req('POST', '/auth/login', { 'X-Device-ID': 'device-admin-001' },  { username: 'admin1', password: 'admin123' });
  check('Login mhs1 berhasil', lMhs.s, 200);
  check('Login dosen1 berhasil', lDosen1.s, 200);
  check('Login dosen2 berhasil', lDosen2.s, 200);
  check('Login admin1 berhasil', lAdmin.s, 200);

  const tMhs    = lMhs.b.data?.access_token;
  const tDosen1 = lDosen1.b.data?.access_token;
  const tDosen2 = lDosen2.b.data?.access_token;
  const tAdmin  = lAdmin.b.data?.access_token;
  const rMhs    = lMhs.b.data?.refresh_token;

  // ── Token Binding ───────────────────────────────────────────────────────────
  console.log('\n[3] Token Binding & Device Check');
  check('Token mhs1 + device mhs2 → 403 (token binding)',
    (await req('GET', '/nilai', { 'Authorization': `Bearer ${tMhs}`, 'X-Device-ID': 'device-mhs-002' })).s, 403);
  check('Tanpa token → 401',
    (await req('GET', '/nilai')).s, 401);

  // ── Akses Langsung ke Service (bypass gateway) ──────────────────────────────
  console.log('\n[4] Proteksi akses langsung ke service');
  check('GET /nilai langsung port 3001 tanpa gateway secret → 403',
    (await req('GET', '/nilai', { 'Authorization': `Bearer ${tMhs}` }, null, 3001)).s, 403);
  check('GET /transkrip/2021001 langsung port 3002 tanpa gateway secret → 403',
    (await req('GET', '/transkrip/2021001', { 'Authorization': `Bearer ${tMhs}` }, null, 3002)).s, 403);

  // ── GET /nilai ───────────────────────────────────────────────────────────────
  console.log('\n[5] GET /nilai — Least Privilege');
  const rMhsNilai = await req('GET', '/nilai', { 'Authorization': `Bearer ${tMhs}`, 'X-Device-ID': 'device-mhs-001' });
  check('mhs1 lihat nilai sendiri (2 baris) → 200',
    rMhsNilai.s, 200, `${rMhsNilai.b.data?.nilai?.length} rows`);
  const rDosenNilai = await req('GET', '/nilai', { 'Authorization': `Bearer ${tDosen1}`, 'X-Device-ID': 'device-dosen-001' });
  check('dosen1 lihat nilai kelas ampuannya (3 baris) → 200',
    rDosenNilai.s, 200, `${rDosenNilai.b.data?.nilai?.length} rows`);

  // ── PUT /nilai/:id ───────────────────────────────────────────────────────────
  console.log('\n[6] PUT /nilai/:id — Dosen edit nilai');
  check('dosen1 update nilai mhs1 kelas PW (id=1) → 200',
    (await req('PUT', '/nilai/1', { 'Authorization': `Bearer ${tDosen1}`, 'X-Device-ID': 'device-dosen-001' }, { nilai: 90 })).s, 200);
  check('dosen2 update nilai kelas dosen1 → 403 (bukan ampuan)',
    (await req('PUT', '/nilai/1', { 'Authorization': `Bearer ${tDosen2}`, 'X-Device-ID': 'device-dosen-002' }, { nilai: 55 })).s, 403);
  check('mahasiswa update nilai → 403',
    (await req('PUT', '/nilai/1', { 'Authorization': `Bearer ${tMhs}`, 'X-Device-ID': 'device-mhs-001' }, { nilai: 100 })).s, 403);
  check('nilai 150 → 400 (validasi range)',
    (await req('PUT', '/nilai/1', { 'Authorization': `Bearer ${tDosen1}`, 'X-Device-ID': 'device-dosen-001' }, { nilai: 150 })).s, 400);
  check('nilai -5 → 400 (validasi range)',
    (await req('PUT', '/nilai/1', { 'Authorization': `Bearer ${tDosen1}`, 'X-Device-ID': 'device-dosen-001' }, { nilai: -5 })).s, 400);

  // ── POST /kelas/finalisasi ───────────────────────────────────────────────────
  console.log('\n[7] POST /kelas/:id/finalisasi + Sinkron Transkrip');
  check('dosen2 finalisasi kelas dosen1 → 403',
    (await req('POST', '/kelas/1/finalisasi', { 'Authorization': `Bearer ${tDosen2}`, 'X-Device-ID': 'device-dosen-002' })).s, 403);
  const rFin = await req('POST', '/kelas/1/finalisasi', { 'Authorization': `Bearer ${tDosen1}`, 'X-Device-ID': 'device-dosen-001' });
  check('dosen1 finalisasi kelas PW → 200', rFin.s, 200, rFin.b.data?.sinkron?.success ? 'sync OK' : 'sync GAGAL');
  check('dosen1 finalisasi kelas yg sudah final → 403',
    (await req('POST', '/kelas/1/finalisasi', { 'Authorization': `Bearer ${tDosen1}`, 'X-Device-ID': 'device-dosen-001' })).s, 403);
  check('dosen1 update nilai kelas final → 403',
    (await req('PUT', '/nilai/1', { 'Authorization': `Bearer ${tDosen1}`, 'X-Device-ID': 'device-dosen-001' }, { nilai: 70 })).s, 403);

  // ── GET /transkrip ───────────────────────────────────────────────────────────
  console.log('\n[8] GET /transkrip/:nim — Least Privilege');
  const rTr = await req('GET', '/transkrip/2021001', { 'Authorization': `Bearer ${tMhs}`, 'X-Device-ID': 'device-mhs-001' });
  check('mhs1 lihat transkrip NIM sendiri → 200', rTr.s, 200, `${rTr.b.data?.transkrip?.length} entries`);
  check('mhs1 lihat transkrip NIM orang lain → 403',
    (await req('GET', '/transkrip/2021002', { 'Authorization': `Bearer ${tMhs}`, 'X-Device-ID': 'device-mhs-001' })).s, 403);
  check('admin lihat transkrip siapapun → 200',
    (await req('GET', '/transkrip/2021002', { 'Authorization': `Bearer ${tAdmin}`, 'X-Device-ID': 'device-admin-001' })).s, 200);
  check('dosen lihat transkrip → 403',
    (await req('GET', '/transkrip/2021001', { 'Authorization': `Bearer ${tDosen1}`, 'X-Device-ID': 'device-dosen-001' })).s, 403);

  // ── Token Service ────────────────────────────────────────────────────────────
  console.log('\n[9] POST /transkrip/sinkron — hanya token service');
  check('mahasiswa POST /transkrip/sinkron → 403',
    (await req('POST', '/transkrip/sinkron', { 'Authorization': `Bearer ${tMhs}`, 'X-Device-ID': 'device-mhs-001' }, { kelas_id: 1 })).s, 403);
  check('admin POST /transkrip/sinkron → 403',
    (await req('POST', '/transkrip/sinkron', { 'Authorization': `Bearer ${tAdmin}`, 'X-Device-ID': 'device-admin-001' }, { kelas_id: 1 })).s, 403);

  // ── Refresh & Logout + Blacklist ─────────────────────────────────────────────
  console.log('\n[10] Refresh Token & Logout + Token Blacklist');
  check('Refresh token mhs1 → 200',
    (await req('POST', '/auth/refresh', { 'X-Device-ID': 'device-mhs-001' }, { refresh_token: rMhs })).s, 200);
  check('Logout mhs1 → 200',
    (await req('POST', '/auth/logout', { 'Authorization': `Bearer ${tMhs}`, 'X-Device-ID': 'device-mhs-001' }, { refresh_token: rMhs })).s, 200);
  check('Token MHS1 setelah logout di-blacklist → 403',
    (await req('GET', '/nilai', { 'Authorization': `Bearer ${tMhs}`, 'X-Device-ID': 'device-mhs-001' })).s, 403);
  check('Refresh token yg sudah dicabut → 401',
    (await req('POST', '/auth/refresh', { 'X-Device-ID': 'device-mhs-001' }, { refresh_token: rMhs })).s, 401);

  // ── Admin Audit ──────────────────────────────────────────────────────────────
  console.log('\n[11] Admin Audit Log & Trail');
  const rLog = await req('GET', '/admin/audit-log?limit=200', { 'Authorization': `Bearer ${tAdmin}`, 'X-Device-ID': 'device-admin-001' });
  check('admin GET /admin/audit-log → 200', rLog.s, 200, `${rLog.b.data?.total} total entries`);
  const rLogDeny = await req('GET', '/admin/audit-log?result=deny&limit=200', { 'Authorization': `Bearer ${tAdmin}`, 'X-Device-ID': 'device-admin-001' });
  check('admin filter audit-log deny → 200', rLogDeny.s, 200, `${rLogDeny.b.data?.rows?.length} deny entries`);
  const rTrail = await req('GET', '/admin/audit-trail?limit=200', { 'Authorization': `Bearer ${tAdmin}`, 'X-Device-ID': 'device-admin-001' });
  check('admin GET /admin/audit-trail → 200', rTrail.s, 200, `${rTrail.b.data?.total} total entries`);
  const rTrailFin = await req('GET', '/admin/audit-trail?action=FINALISASI_KELAS', { 'Authorization': `Bearer ${tAdmin}`, 'X-Device-ID': 'device-admin-001' });
  check('admin filter trail FINALISASI_KELAS → 200', rTrailFin.s, 200, `${rTrailFin.b.data?.rows?.length} entries`);
  check('mahasiswa akses audit-log → 403',
    (await req('GET', '/admin/audit-log', { 'Authorization': `Bearer ${(await req('POST', '/auth/login', { 'X-Device-ID': 'device-mhs-002' }, { username: 'mhs2', password: 'mhs456' })).b.data?.access_token}`, 'X-Device-ID': 'device-mhs-002' })).s, 403);

  // ── POST /auth/service ───────────────────────────────────────────────────────
  console.log('\n[12] Token Service Authentication');
  check('POST /auth/service client salah → 401',
    (await req('POST', '/auth/service', {}, { client_id: 'salah', client_secret: 'salah' })).s, 401);
  check('POST /auth/service valid → 200',
    (await req('POST', '/auth/service', {}, { client_id: process.env.SERVICE_CLIENT_ID, client_secret: process.env.SERVICE_CLIENT_SECRET })).s, 200);

  // ── Frontend tersedia ────────────────────────────────────────────────────────
  console.log('\n[13] Frontend static files');
  const fIndex = await req('GET', '/index.html', {}, null, 3000);
  check('GET /index.html → 200', fIndex.s, 200);
  const fMhs = await req('GET', '/mahasiswa.html', {}, null, 3000);
  check('GET /mahasiswa.html → 200', fMhs.s, 200);
  const fDosen = await req('GET', '/dosen.html', {}, null, 3000);
  check('GET /dosen.html → 200', fDosen.s, 200);
  const fAdmin = await req('GET', '/admin.html', {}, null, 3000);
  check('GET /admin.html → 200', fAdmin.s, 200);

  // ── HASIL ────────────────────────────────────────────────────────────────────
  const total = pass + fail;
  console.log('\n══════════════════════════════════════════════════');
  console.log(`  HASIL AKHIR: ${pass}/${total} passed${fail > 0 ? ` — ${fail} FAILED ✗` : ' — SEMUA LULUS ✓'}`);
  console.log('══════════════════════════════════════════════════\n');

  if (fail > 0) process.exit(1);
}

run().catch(e => { console.error('FATAL:', e); process.exit(1); });
