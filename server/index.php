<?php
// =====================================================================
// index.php  --  API Mahasiswa (versi sederhana)
//
// Semua alamat masuk ke file ini berkat .htaccess. Alurnya:
//   1. Baca alamat (URL) dan jenis request (GET/POST/PUT/DELETE)
//   2. Tentukan mau ke mana (routing)
//   3. Jalankan query database
//   4. Kirim jawaban JSON  (+ catat ke tabel log_api)
//
// Daftar endpoint:
//   POST   /register  -> daftar akun baru                     (publik)
//   POST   /login      -> login, mendapat token JWT          (publik)
//   GET    /me         -> lihat data akun yang sedang login  (perlu token)
//   PUT    /me/password-> ganti password sendiri             (perlu token)
//   GET    /mhs        -> ambil semua mahasiswa              (perlu token)
//   GET    /mhs/3      -> ambil mahasiswa dengan id 3        (perlu token)
//   POST   /mhs        -> tambah mahasiswa baru              (token + role admin)
//   PUT    /mhs/3      -> ubah data mahasiswa id 3           (token + role admin/dosen)
//   DELETE /mhs/3      -> hapus mahasiswa id 3               (token + role admin)
//   GET    /log        -> lihat 20 catatan log terakhir      (token + role admin)
//
// Perubahan dari Pertemuan 6 ditandai komentar  "<-- BARU P7"
// =====================================================================

require 'koneksi.php';   // menghasilkan variabel $db (koneksi database) + pengaturan keamanan
require 'jwt.php';       // <-- BARU P7: fungsi buat_token() dan cek_token()
require 'fungsi.php';    // fungsi kirim(), catat_log(), wajib_login(), wajib_admin(), ...

// ---------------------------------------------------------------------
// Izin untuk client web (browser) yang alamatnya berbeda dari server ini.
// Tanpa ini browser akan memblokir permintaan (aturan CORS).
// ---------------------------------------------------------------------
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');   // <-- BARU P7: izinkan header Authorization

// Browser kadang bertanya dulu "boleh tidak?" dengan method OPTIONS. Jawab saja "boleh".
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ---------------------------------------------------------------------
// LANGKAH 1: membaca alamat
// Contoh alamat: /api-mhs-sederhana/server/mhs/3
// Kita buang folder server-nya, sisanya "mhs/3" dipecah jadi ['mhs', '3'].
// ---------------------------------------------------------------------
$path   = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);   // tanpa ?query
$folder = dirname($_SERVER['SCRIPT_NAME']);                   // folder tempat index.php
if ($folder != '/' && strpos($path, $folder) === 0) {
    $path = substr($path, strlen($folder));                   // buang nama folder
}
$bagian   = explode('/', trim($path, '/'));                   // pecah per tanda "/"
$resource = $bagian[0];                                       // 'mhs' atau 'log'
$id       = isset($bagian[1]) ? $bagian[1] : null;            // '3' (boleh kosong)

$method = $_SERVER['REQUEST_METHOD'];                         // GET / POST / PUT / DELETE

// Data JSON yang dikirim client (untuk POST dan PUT), diubah menjadi array PHP.
$input = json_decode(file_get_contents('php://input'), true);

// <-- BARU P7: RATE LIMITING umum. Terlalu banyak request dari satu IP -> 429.
batasi_request();

// try ... catch : jika ada error database, jangan tampilkan layar error PHP,
// tapi kirim jawaban JSON yang rapi.
try {

    // =================================================================
    // <-- BARU P7: POST /register  -> DAFTAR AKUN BARU (publik)
    // Username unik, password minimal 8 karakter, role otomatis 'user'.
    // =================================================================
    if ($resource == 'register' && $method == 'POST') {

        // 1) Validasi input: username dan password wajib diisi (teks).
        if (!is_array($input) || empty($input['username']) || empty($input['password'])
            || !is_string($input['username']) || !is_string($input['password'])) {
            kirim(['status' => 'error', 'pesan' => 'username dan password wajib diisi'], 422);
        }
        $username = trim($input['username']);

        // Username harus 3-50 karakter, hanya huruf/angka/_/-.
        if (!preg_match('/^[a-zA-Z0-9_-]{3,50}$/', $username)) {
            kirim(['status' => 'error', 'pesan' => 'Username 3-50 karakter (huruf, angka, _, -)'], 422);
        }

        // Password minimal 8 karakter.
        if (strlen($input['password']) < 8) {
            kirim(['status' => 'error', 'pesan' => 'Password minimal 8 karakter'], 422);
        }

        // 2) Cek keunikan username.
        $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            kirim(['status' => 'error', 'pesan' => 'Username sudah terdaftar'], 409);
        }

        // 3) Simpan dengan password_hash (BUKAN teks asli). Role otomatis 'user'.
        $password_hash = password_hash($input['password'], PASSWORD_DEFAULT);
        $stmt = $db->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')");
        $stmt->execute([$username, $password_hash]);

        $idBaru = $db->lastInsertId();
        kirim([
            'status'  => 'sukses',
            'pesan'   => 'Akun terdaftar, silakan login',
            'user'    => ['id' => (int)$idBaru, 'username' => $username, 'role' => 'user']
        ], 201);
    }

    // =================================================================
    // <-- BARU P7: POST /login  -> AUTENTIKASI (publik, tidak perlu token)
    // =================================================================
    if ($resource == 'login' && $method == 'POST') {

        // 1) Validasi input: username dan password wajib diisi (teks).
        if (!is_array($input) || empty($input['username']) || empty($input['password'])
            || !is_string($input['username']) || !is_string($input['password'])) {
            kirim(['status' => 'error', 'pesan' => 'username dan password wajib diisi'], 422);
        }
        $username = trim($input['username']);
        $username_log = $username;                      // ikut dicatat di log

        // 2) RATE LIMITING login: hitung gagal login untuk username ini dari IP ini dalam 1 menit.
        $semenit_lalu = date('Y-m-d H:i:s', time() - 60);
        $stmt = $db->prepare("SELECT COUNT(*) FROM log_api
                              WHERE ip = ? AND username = ? AND status = 401 AND waktu >= ?
                                AND path LIKE '%/login'");
        $stmt->execute([$_SERVER['REMOTE_ADDR'], $username, $semenit_lalu]);
        if ($stmt->fetchColumn() >= $batas_login) {
            header('Retry-After: 60');
            kirim(['status' => 'error', 'pesan' => 'Terlalu banyak percobaan login. Coba lagi 1 menit lagi'], 429);
        }

        // 3) Cari akun di database (prepared statement -> aman dari SQL Injection).
        $stmt = $db->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $akun = $stmt->fetch();

        // 4) Cocokkan password. password_verify membandingkan password dengan HASH di database.
        //    Pesan error SENGAJA sama untuk "username salah" dan "password salah",
        //    supaya penyerang tidak tahu username mana yang benar-benar ada.
        if (!$akun || !password_verify($input['password'], $akun['password'])) {
            kirim(['status' => 'error', 'pesan' => 'Username atau password salah'], 401);
        }

        // 5) Berhasil -> buat token JWT berisi identitas pengguna (BUKAN password!).
        $token = buat_token(
            ['sub' => (int)$akun['id'], 'username' => $akun['username'], 'role' => $akun['role']],
            $jwt_secret,
            $jwt_berlaku
        );
        kirim([
            'status'        => 'sukses',
            'pesan'         => 'Login berhasil',
            'token'         => $token,
            'tipe'          => 'Bearer',
            'berlaku_detik' => $jwt_berlaku,
            'user'          => ['username' => $akun['username'], 'role' => $akun['role']]
        ]);
    }

    // =================================================================
    // <-- BARU P7: SEMUA alamat di bawah ini WAJIB membawa token yang sah.
    // wajib_login() mengembalikan data pengguna, atau langsung 401 dan berhenti.
    // Catatan: /register dan /login adalah publik (diproses di atas), jadi tidak
    // perlu token. Resource lain (mhs, me, log, log-analisis) wajib login.
    // =================================================================
    elseif ($resource != '' && $resource != 'register' && $resource != 'login') {
        $pengguna = wajib_login();
    }

    // =================================================================
    // LANGKAH 2: ROUTING  -> /me
    // =================================================================
    if ($resource == 'me' && $method == 'GET') {
        kirim(['status' => 'sukses', 'data' => [
            'id' => $pengguna['sub'], 'username' => $pengguna['username'],
            'role' => $pengguna['role'], 'token_habis_pada' => date('Y-m-d H:i:s', $pengguna['exp'])
        ]]);
    }

    // =================================================================
    // <-- BARU P7: PUT /me/password -> GANTI PASSWORD SENDIRI (perlu token)
    // Wajib mengirim password LAMA yang benar, lalu password BARU (>= 8).
    // =================================================================
    elseif ($resource == 'me' && $method == 'PUT') {

        // Validasi body.
        if (!is_array($input) || empty($input['password_lama']) || empty($input['password_baru'])
            || !is_string($input['password_lama']) || !is_string($input['password_baru'])) {
            kirim(['status' => 'error', 'pesan' => 'password_lama dan password_baru wajib diisi'], 422);
        }
        if (strlen($input['password_baru']) < 8) {
            kirim(['status' => 'error', 'pesan' => 'Password baru minimal 8 karakter'], 422);
        }

        // Ambil password lama dari database (harus sama dengan yang di token).
        $stmt = $db->prepare("SELECT id, password FROM users WHERE id = ?");
        $stmt->execute([$pengguna['sub']]);
        $akun = $stmt->fetch();
        if (!$akun) {
            kirim(['status' => 'error', 'pesan' => 'Akun tidak ditemukan'], 404);
        }

        // Wajib mengirim password lama yang BENAR.
        if (!password_verify($input['password_lama'], $akun['password'])) {
            kirim(['status' => 'error', 'pesan' => 'Password lama salah'], 401);
        }

        // Simpan password BARU dalam bentuk hash.
        $password_hash = password_hash($input['password_baru'], PASSWORD_DEFAULT);
        $stmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$password_hash, $pengguna['sub']]);

        kirim(['status' => 'sukses', 'pesan' => 'Password diubah, silakan login dengan password baru']);
    }

    // =================================================================
    // ROUTING  -> /mhs
    // =================================================================
    elseif ($resource == 'mhs') {

        // ---------- ID harus angka (jika diisi) ----------
        if ($id !== null && !ctype_digit($id)) {
            kirim(['status' => 'error', 'pesan' => 'ID harus berupa angka'], 400);
        }

        // ---------- READ: GET /mhs  (semua data) ----------
        if ($method == 'GET' && $id === null) {
            $hasil = $db->query("SELECT * FROM mhs ORDER BY id")->fetchAll();
            kirim(['status' => 'sukses', 'data' => $hasil]);
        }

        // ---------- READ: GET /mhs/3  (satu data) ----------
        elseif ($method == 'GET') {
            $stmt = $db->prepare("SELECT * FROM mhs WHERE id = ?");
            $stmt->execute([$id]);
            $baris = $stmt->fetch();                  // false jika tidak ada
            if (!$baris) {
                kirim(['status' => 'error', 'pesan' => 'Mahasiswa tidak ditemukan'], 404);
            }
            kirim(['status' => 'sukses', 'data' => $baris]);
        }

        // ---------- CREATE: POST /mhs ----------
        elseif ($method == 'POST' && $id === null) {
            wajib_admin($pengguna);                   // <-- BARU P7: OTORISASI, hanya admin
            cek_input($input);                        // data wajib lengkap, jika tidak -> berhenti (400)

            // NIM tidak boleh kembar
            $stmt = $db->prepare("SELECT id FROM mhs WHERE nim = ?");
            $stmt->execute([$input['nim']]);
            if ($stmt->fetch()) {
                kirim(['status' => 'error', 'pesan' => 'NIM sudah terdaftar'], 409);
            }

            $stmt = $db->prepare("INSERT INTO mhs (nim, name, major) VALUES (?, ?, ?)");
            $stmt->execute([$input['nim'], $input['name'], $input['major']]);

            $idBaru = $db->lastInsertId();            // id yang baru dibuat MySQL
            kirim(['status' => 'sukses', 'pesan' => 'Data ditambahkan', 'id' => (int)$idBaru], 201);
        }

        // ---------- UPDATE: PUT /mhs/3 ----------
        elseif ($method == 'PUT' && $id !== null) {
            wajib_role($pengguna, ['admin', 'dosen']);   // <-- BARU P7: admin DAN dosen boleh ubah
            cek_input($input);

            // Pastikan datanya ada dulu
            $stmt = $db->prepare("SELECT id FROM mhs WHERE id = ?");
            $stmt->execute([$id]);
            if (!$stmt->fetch()) {
                kirim(['status' => 'error', 'pesan' => 'Mahasiswa tidak ditemukan'], 404);
            }

            // NIM baru tidak boleh dipakai mahasiswa LAIN (id <> ?)
            $stmt = $db->prepare("SELECT id FROM mhs WHERE nim = ? AND id <> ?");
            $stmt->execute([$input['nim'], $id]);
            if ($stmt->fetch()) {
                kirim(['status' => 'error', 'pesan' => 'NIM sudah dipakai mahasiswa lain'], 409);
            }

            $stmt = $db->prepare("UPDATE mhs SET nim = ?, name = ?, major = ? WHERE id = ?");
            $stmt->execute([$input['nim'], $input['name'], $input['major'], $id]);
            kirim(['status' => 'sukses', 'pesan' => 'Data diubah']);
        }

        // ---------- DELETE: DELETE /mhs/3 ----------
        elseif ($method == 'DELETE' && $id !== null) {
            wajib_admin($pengguna);                   // <-- BARU P7
            $stmt = $db->prepare("DELETE FROM mhs WHERE id = ?");
            $stmt->execute([$id]);
            if ($stmt->rowCount() == 0) {             // tidak ada baris yang terhapus
                kirim(['status' => 'error', 'pesan' => 'Mahasiswa tidak ditemukan'], 404);
            }
            kirim(['status' => 'sukses', 'pesan' => 'Data dihapus']);
        }

        // ---------- Kombinasi lain (mis. DELETE /mhs tanpa id) ----------
        else {
            kirim(['status' => 'error', 'pesan' => 'Method tidak diizinkan'], 405);
        }
    }

    // =================================================================
    // ROUTING  -> /log   (melihat catatan log dari database)
    // =================================================================
    elseif ($resource == 'log' && $method == 'GET') {
        wajib_admin($pengguna);                       // <-- BARU P7: log hanya boleh dilihat admin
        $hasil = $db->query("SELECT * FROM log_api ORDER BY id DESC LIMIT 20")->fetchAll();
        // Perhatian: kirim() juga mencatat request /log ini ke log_api.
        kirim(['status' => 'sukses', 'data' => $hasil]);
    }

    // =================================================================
    // <-- BARU P7: GET /log-analisis -> 3 query analisis log_api
    //   1) jumlah login gagal per username
    //   2) 5 IP dengan request terbanyak
    //   3) jumlah 401/403/429 per hari
    // Hanya admin.
    // =================================================================
    elseif ($resource == 'log-analisis' && $method == 'GET') {
        wajib_admin($pengguna);

        // 1) Jumlah login gagal (status 401 pada path /login) per username.
        $q1 = $db->query("SELECT username, COUNT(*) AS jumlah
                          FROM log_api
                          WHERE path LIKE '%/login%' AND status = 401
                          GROUP BY username ORDER BY jumlah DESC")->fetchAll();

        // 2) 5 IP dengan request terbanyak (seluruh periode).
        $q2 = $db->query("SELECT ip, COUNT(*) AS jumlah
                          FROM log_api
                          GROUP BY ip ORDER BY jumlah DESC LIMIT 5")->fetchAll();

        // 3) Jumlah 401/403/429 per hari.
        $q3 = $db->query("SELECT DATE(waktu) AS hari,
                                 SUM(status = 401) AS cnt_401,
                                 SUM(status = 403) AS cnt_403,
                                 SUM(status = 429) AS cnt_429,
                                 COUNT(*) AS total
                          FROM log_api
                          WHERE status IN (401, 403, 429)
                          GROUP BY DATE(waktu) ORDER BY hari DESC LIMIT 30")->fetchAll();

        kirim(['status' => 'sukses', 'data' => [
            'login_gagal_per_username' => $q1,
            'ip_terbanyak'            => $q2,
            'error_per_hari'          => $q3,
        ]]);
    }

    // =================================================================
    // ROUTING  -> alamat kosong  (cek server hidup)
    // =================================================================
    elseif ($resource == '') {
        kirim(['status' => 'sukses', 'pesan' => 'API Mahasiswa aktif']);
    }

    // Alamat lain yang tidak dikenal
    else {
        kirim(['status' => 'error', 'pesan' => 'Alamat tidak ditemukan'], 404);
    }

} catch (PDOException $e) {
    // Error database tak terduga. Detailnya TIDAK dikirim ke client (bisa membocorkan struktur tabel).
    kirim(['status' => 'error', 'pesan' => 'Terjadi kesalahan pada database'], 500);
}


// =====================================================================
// FUNGSI: cek_input()  -- memastikan data dari client lengkap
// Jika ada yang kurang, langsung kirim error 400 dan berhenti.
// =====================================================================
function cek_input($input)
{
    // Jika body bukan JSON yang benar, $input bukan array.
    if (!is_array($input)) {
        kirim(['status' => 'error', 'pesan' => 'Kirim data dalam format JSON'], 400);
    }

    // Tiga field ini wajib ada dan tidak boleh kosong.
    foreach (['nim', 'name', 'major'] as $field) {
        if (empty($input[$field])) {
            kirim(['status' => 'error', 'pesan' => "Field $field wajib diisi"], 422);
        }
    }

    // NIM harus angka saja.
    if (!ctype_digit((string)$input['nim'])) {
        kirim(['status' => 'error', 'pesan' => 'NIM harus berupa angka'], 422);
    }
}
