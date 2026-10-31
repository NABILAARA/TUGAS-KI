# Sistem Nilai Zero Trust

Tugas Praktikum Individu — Zero Trust Security  
Mata Kuliah Keamanan Informasi 

Nabila Rohmatul Aulia
247006111143
Kelas E

---

## Cara Menjalankan

### 1. Persyaratan

- Node.js v18 atau lebih baru
- npm

### 2. Install Dependencies

```bash
npm install
```

### 3. Konfigurasi Environment

Salin `.env.example` menjadi `.env`:

```bash
cp .env.example .env
```

Lalu generate secret untuk setiap placeholder `GANTI_DENGAN_HASIL_openssl_rand_hex_32`:

```bash
openssl rand -hex 32
```

Isi minimal 32 karakter untuk `JWT_SECRET`, `GATEWAY_SECRET`, `INTERNAL_SECRET`, dan `SERVICE_CLIENT_SECRET`. Gateway akan crash saat startup jika ada secret kurang dari 32 karakter.

### 4. Seed Data Awal

```bash
npm run seed
```

Perintah ini membuat database SQLite (`database/sistem_nilai.db`) dan mengisi data awal: 1 admin, 2 dosen, 3 mahasiswa, 2 kelas, 1 device per user.

### 5. Jalankan Semua Service

Buka **3 terminal terpisah**, jalankan masing-masing:

**Terminal 1 — Gateway (port 3000):**
```bash
npm run gateway
```

**Terminal 2 — Service Nilai (port 3001):**
```bash
npm run nilai
```

**Terminal 3 — Service Transkrip (port 3002):**
```bash
npm run transkrip
```

### 6. Buka Aplikasi

Buka browser dan akses:

```
http://localhost:3000
```

### 7. Set Device ID di Browser (Penting)

Device ID di-generate otomatis dan disimpan di `localStorage`. Agar cocok dengan device yang terdaftar di database, jalankan ini di **Console browser (F12)** sebelum login:

```js
// Contoh untuk login sebagai mhs1
localStorage.setItem('zt_device_id', 'device-mhs-001')
```

Lalu refresh halaman, lalu login. Ganti nilai sesuai akun yang dipakai (lihat tabel di bawah).

---

## Akun & Device ID Data Awal

| Username | Password  | Role       | Nama             | NIM     | Device ID          |
|----------|-----------|------------|------------------|---------|--------------------|
| admin1   | admin123  | admin      | Administrator    | —       | device-admin-001   |
| dosen1   | dosen123  | dosen      | Dr. Andi Wijaya  | —       | device-dosen-001   |
| dosen2   | dosen456  | dosen      | Dr. Siti Rahayu  | —       | device-dosen-002   |
| mhs1     | mhs123    | mahasiswa  | Budi Santoso     | 2021001 | device-mhs-001     |
| mhs2     | mhs456    | mahasiswa  | Citra Dewi       | 2021002 | device-mhs-002     |
| mhs3     | mhs789    | mahasiswa  | Dian Pratama     | 2021003 | device-mhs-003     |

---

## Kelas & Nilai Awal

| Kelas                | Dosen Pengampu | Mahasiswa         | Nilai Awal         |
|----------------------|----------------|-------------------|--------------------|
| Pemrograman Web      | dosen1         | mhs1, mhs2, mhs3  | 72, 85, 60         |
| Keamanan Informasi   | dosen2         | mhs1, mhs2, mhs3  | 68, 78, 91         |

---

## Konfigurasi Jam Akses

Jam akses untuk operasi **ubah nilai** dan **finalisasi kelas** dikontrol via `.env`:

```env
ACCESS_HOUR_START=7    # mulai jam 07:00 (default di .env.example)
ACCESS_HOUR_END=21    # sampai jam 21:00
```

Untuk demo tanpa batasan jam (akses kapan saja):

```env
ACCESS_HOUR_START=0
ACCESS_HOUR_END=24
```

---

## Pengujian

### Otomatis (46 test case)

```bash
node test_final.js
```

Test mencakup: health check, autentikasi, token binding, proteksi akses langsung ke service, least privilege, edit nilai, finalisasi + sinkron transkrip, transkrip access control, refresh token, logout + token blacklist, admin audit log/trail, token service, dan frontend static files.

### Manual dengan curl

**Login:**
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: device-mhs-001" \
  -d '{"username":"mhs1","password":"mhs123"}'
```

**Lihat Nilai (Mahasiswa):**
```bash
curl http://localhost:3000/nilai \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Device-ID: device-mhs-001"
```

**Update Nilai (Dosen):**
```bash
curl -X PUT http://localhost:3000/nilai/1 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <access_token_dosen>" \
  -H "X-Device-ID: device-dosen-001" \
  -d '{"nilai":88}'
```

**Finalisasi Kelas:**
```bash
curl -X POST http://localhost:3000/kelas/1/finalisasi \
  -H "Authorization: Bearer <access_token_dosen>" \
  -H "X-Device-ID: device-dosen-001"
```

**Lihat Transkrip:**
```bash
curl http://localhost:3000/transkrip/2021001 \
  -H "Authorization: Bearer <access_token>" \
  -H "X-Device-ID: device-mhs-001"
```

**Audit Log (Admin):**
```bash
curl "http://localhost:3000/admin/audit-log?result=deny" \
  -H "Authorization: Bearer <access_token_admin>" \
  -H "X-Device-ID: device-admin-001"
```

**Audit Trail (Admin):**
```bash
curl "http://localhost:3000/admin/audit-trail?action=UPDATE_NILAI" \
  -H "Authorization: Bearer <access_token_admin>" \
  -H "X-Device-ID: device-admin-001"
```

---

## Arsitektur

```
Client (Browser / curl)
        │
        │ access token (JWT) + X-Device-ID header
        ▼
┌─────────────────────────────────┐
│   API Gateway  (port 3000)      │  ← PEP: satu-satunya pintu masuk
│   - Verifikasi JWT + blacklist  │
│   - Cek device terdaftar         │
│   - Policy Engine (allow/deny)  │  ← PDP: keputusan berbasis DB
│   - Rate limiting login         │
│   - Audit log setiap request    │
└────────────┬────────────────────┘
             │ X-Gateway-Secret header
     ┌───────┴────────┐
     ▼                ▼
┌──────────┐   ┌──────────────┐
│  Nilai   │   │  Transkrip   │   ← Bind 127.0.0.1, tidak expose
│ :3001    │   │  :3002       │   ← Verifikasi JWT mandiri (assume breach)
└────┬─────┘   └──────┬───────┘
     │                │
     ▼                ▼
┌─────────────────────────┐
│  SQLite (better-sqlite3)│  ← WAL mode, multi-process concurrent
│  database/sistem_nilai.db│
└─────────────────────────┘
```

---

## Struktur File

```
zero-trust-sistem-nilai/
├── gateway/
│   ├── index.js        # Gateway: auth endpoints, proxy, rate limiting, admin endpoints
│   ├── policy.js       # Policy Engine: evaluasi allow/deny + token binding + jam akses
│   ├── audit.js        # Penulis audit_log (keputusan akses)
│   └── trail.js        # Penulis audit_trail (mutasi data)
├── service-nilai/
│   └── index.js        # Service Nilai: GET/PUT nilai, finalisasi + sinkron transkrip
├── service-transkrip/
│   └── index.js        # Service Transkrip: GET transkrip, POST sinkron
├── database/
│   ├── db.js           # Koneksi SQLite (better-sqlite3), schema, immutable triggers
│   └── seed.js         # Data awal: 6 user, 6 device, 2 kelas, 6 nilai
├── frontend/
│   ├── index.html      # Halaman login
│   ├── mahasiswa.html  # Dashboard mahasiswa (nilai + transkrip)
│   ├── dosen.html      # Dashboard dosen (edit nilai + finalisasi)
│   ├── admin.html      # Dashboard admin (transkrip + audit log + audit trail)
│   └── app.js          # Shared helper: token, device ID, fetch wrapper, logout
├── test_final.js       # 46 test case end-to-end
├── .env.example        # Template environment (di-commit)
├── .env                # Secret asli (TIDAK di-commit)
├── .gitignore
└── package.json
```

---

## Prinsip Zero Trust yang Diterapkan

| Prinsip | Implementasi |
|---|---|
| **Never trust, always verify** | Setiap request dicek: JWT signature + expiry, JTI blacklist, device terdaftar, token binding, kepemilikan data |
| **Least privilege** | Policy engine query DB per request untuk cek kepemilikan data, bukan hanya lihat role di token |
| **Assume breach** | Service verifikasi JWT + gateway secret secara mandiri, tidak percaya gateway begitu saja |

## Fitur Keamanan

| Fitur | Detail |
|---|---|
| Access token JWT 10 menit | Payload: `sub`, `role`, `device_id`, `jti` |
| Refresh token 1 hari | Disimpan sebagai SHA-256 hash di DB, bukan plaintext |
| Token service 5 menit | Role `service`, untuk komunikasi antar-service saja |
| Token binding ke device | `device_id` di JWT payload, dicocokkan dengan header `X-Device-ID` |
| Token blacklist | JTI di-blacklist saat logout, access token langsung tidak valid |
| Gateway secret | Service menolak request tanpa header `X-Gateway-Secret` |
| Rate limiting | 5 percobaan login gagal per IP per menit |
| Validasi input nilai | Range 0–100, tolak di luar range dengan HTTP 400 |
| Jam akses | PUT nilai & finalisasi dibatasi jam tertenu (configurable via `.env`) |
| Audit log | Setiap keputusan akses (allow/deny + alasan), immutable |
| Audit trail | Mutasi data dengan before/after JSON, immutable |
| Immutable audit | SQLite trigger mencegah DELETE/UPDATE di tabel audit |
| Startup validation | Gateway crash jika ada secret < 32 karakter |
| Cleanup expired tokens | Refresh token & blacklist kedaluwarsa dihapus saat startup |

---

## Dependencies

| Package | Fungsi |
|---|---|
| `express` | Web framework untuk gateway dan service |
| `jsonwebtoken` | Generate & verifikasi JWT |
| `better-sqlite3` | Database SQLite (native binding, WAL mode) |
| `bcryptjs` | Hash password |
| `cors` | Cross-origin resource sharing |
| `dotenv` | Load environment variables dari `.env` |
| `http-proxy-middleware` | Proxy request dari gateway ke service |
| `express-rate-limit` | Rate limiting di endpoint login |
