# API Mahasiswa + Autentikasi JWT (Pertemuan 7) — PHP + MySQL

1. Impor `database/mhs.sql` (phpMyAdmin) — membuat tabel mhs, users, log_api.
2. Salin folder ke `htdocs`. Server: http://localhost/api-mhs-auth/server
3. Uji: `php client/test_client.php http://localhost/api-mhs-auth/server`
4. Client web: buka `client/index.html`. Akun: admin/admin123 (admin), budi/budi123 (user).
5. Latihan: `php latihan/jwt_demo.php`, `php latihan/uji_rate_limit.php <url>`
6. Akun latihan: admin/admin123 (admin), budi/budi123 (user), dosen/dosen123 (dosen).
7. Fitur baru Pertemuan 7: POST /register (publik), PUT /me/password (perlu token),
   role dosen (boleh PUT /mhs, tidak boleh DELETE/POST), GET /log-analisis (admin).
Tanpa Apache: `cd server && php -S localhost:8000 router.php`

## Ringkasan hak akses (otorisasi)

| Endpoint | publik | user | dosen | admin |
|---|:---:|:---:|:---:|:---:|
| `POST /register` | ✅ | ✅ | ✅ | ✅ |
| `POST /login` | ✅ | ✅ | ✅ | ✅ |
| `GET /me` | ❌ 401 | ✅ | ✅ | ✅ |
| `PUT /me/password` | ❌ 401 | ✅ | ✅ | ✅ |
| `GET /mhs`, `GET /mhs/{id}` | ❌ 401 | ✅ | ✅ | ✅ |
| `POST /mhs` | ❌ 401 | ❌ 403 | ❌ 403 | ✅ |
| `PUT /mhs/{id}` | ❌ 401 | ❌ 403 | ✅ | ✅ |
| `DELETE /mhs/{id}` | ❌ 401 | ❌ 403 | ❌ 403 | ✅ |
| `GET /log`, `GET /log-analisis` | ❌ 401 | ❌ 403 | ❌ 403 | ✅ |

## Hasil pengujian otomatis

Diuji dengan PHP 8.5.12 + MySQL 8.4.3 memakai server bawaan PHP:

```
cd server
php -S localhost:8000 router.php
cd ..
php client/test_client.php http://localhost:8000
```

Hasil terakhir: **48 dari 48 pengujian lulus (0 gagal)**.
Log lengkap ada di [`docs/hasil-uji.txt`](docs/hasil-uji.txt).

Pengujian mencakup autentikasi, token palsu/rusak, otorisasi per role, CRUD admin,
rate limiting login, logging, register, ganti password, role dosen, dan analisis log.
