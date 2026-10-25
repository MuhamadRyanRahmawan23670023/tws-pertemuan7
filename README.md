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
