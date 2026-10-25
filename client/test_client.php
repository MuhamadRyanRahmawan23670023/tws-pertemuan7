<?php
// =====================================================================
// test_client.php  --  CLIENT penguji API (Pertemuan 7: dengan autentikasi)
//
// Program ini berperan sebagai "pengguna" API: login, memakai token, lalu
// memeriksa apakah server menolak / menerima dengan benar. Hasil: PASS / FAIL.
//
// Jalankan:
//   php test_client.php http://localhost/api-mhs-auth/server
//   php test_client.php http://localhost:8000          <- jika memakai php -S
// =====================================================================

// Boleh lewat terminal (argumen) atau browser (?base=...)
$base = $argv[1] ?? ($_GET['base'] ?? 'http://localhost/api-mhs-auth/server');
$base = rtrim($base, '/');
if (php_sapi_name() != 'cli') header('Content-Type: text/plain; charset=utf-8');

$lulus = 0;
$gagal = 0;

// ---------------------------------------------------------------------
// panggil() : mengirim satu request ke server dengan cURL
//   $token (opsional) -> dikirim sebagai header  Authorization: Bearer <token>
//   Mengembalikan array: [status code, isi jawaban JSON]
// ---------------------------------------------------------------------
function panggil($method, $path, $data = null, $token = null)
{
    global $base;

    $header = [];
    if ($data !== null) {
        $header[] = 'Content-Type: application/json';
    }
    if ($token !== null) {
        $header[] = 'Authorization: Bearer ' . $token;      // <-- cara membawa token
    }

    $ch = curl_init($base . $path);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);   // sertifikat lokal self-signed
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    if ($data !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }

    $isi    = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    return [$status, json_decode($isi, true)];
}

// Mencatat hasil satu pengujian
function cek($nama, $kondisi)
{
    global $lulus, $gagal;
    if ($kondisi) { $lulus++; echo "  [PASS] $nama\n"; }
    else          { $gagal++; echo "  [FAIL] $nama\n"; }
}

// Login dan mengembalikan token (atau null jika gagal)
function login($username, $password)
{
    list($status, $json) = panggil('POST', '/login', ['username' => $username, 'password' => $password]);
    return ($status == 200) ? $json['token'] : null;
}

// ---------------------------------------------------------------------
echo "Menguji server: $base\n\n";

list($status, $json) = panggil('GET', '/');

if ($status == 0) {
    $c = curl_init($base . '/'); curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false); curl_exec($c);
    echo "Server tidak bisa dihubungi: " . curl_error($c) . "\n";
    exit(2);
}

if ($status == 429) {
    echo "Server menolak karena terlalu banyak request dari komputer ini (rate limiting).\n";
    echo "Tunggu 1 menit, lalu jalankan lagi.\n";
    exit(3);
}

// ---------------------------------------------------------------------
echo "1. AUTENTIKASI: siapa kamu?\n";
list($status, $json) = panggil('GET', '/mhs');
cek('GET /mhs tanpa token -> 401', $status == 401);

list($status, $json) = panggil('POST', '/login', ['username' => 'admin', 'password' => 'salah']);
cek('Login password salah -> 401', $status == 401);

list($status, $json) = panggil('POST', '/login', ['username' => 'tidak_ada', 'password' => 'x']);
cek('Login username tidak ada -> 401 (pesan sama, tidak membocorkan)', $status == 401);

list($status, $json) = panggil('POST', '/login', ['username' => 'admin']);
cek('Login tanpa password -> 422', $status == 422);

list($status, $json) = panggil('POST', '/login', ['username' => "' OR '1'='1", 'password' => "' OR '1'='1"]);
cek("Login dengan SQL Injection ' OR '1'='1 -> 401 (gagal menembus)", $status == 401);

$tokenAdmin = login('admin', 'admin123');
cek('Login admin benar -> dapat token', $tokenAdmin !== null);
$tokenUser = login('budi', 'budi123');
cek('Login budi benar -> dapat token', $tokenUser !== null);

if ($tokenAdmin === null || $tokenUser === null) {
    echo "\nLogin gagal. Pastikan database sudah diimpor dari database/mhs.sql versi Pertemuan 7.\n";
    exit(1);
}

echo "   token berbentuk 3 bagian dipisah titik: " . substr($tokenAdmin, 0, 30) . "...\n";
cek('Token terdiri dari 3 bagian (header.payload.signature)', count(explode('.', $tokenAdmin)) == 3);

list($status, $json) = panggil('GET', '/me', null, $tokenUser);
cek('GET /me dengan token -> 200, username budi', $status == 200 && $json['data']['username'] == 'budi');

echo "\n2. TOKEN PALSU / RUSAK harus ditolak\n";
list($status, $json) = panggil('GET', '/mhs', null, 'ini.bukan.token');
cek('Token asal-asalan -> 401', $status == 401);

// Merusak 1 huruf tanda tangan
$rusak = substr($tokenUser, 0, -2) . (substr($tokenUser, -2) == 'AA' ? 'BB' : 'AA');
list($status, $json) = panggil('GET', '/mhs', null, $rusak);
cek('Tanda tangan diubah -> 401', $status == 401);

// Mengganti isi payload menjadi role admin, tanda tangan tetap yang lama
list($h, $p, $t) = explode('.', $tokenUser);
$payloadPalsu = rtrim(strtr(base64_encode(json_encode(['sub' => 2, 'username' => 'budi', 'role' => 'admin', 'exp' => time() + 3600])), '+/', '-_'), '=');
list($status, $json) = panggil('GET', '/mhs', null, "$h.$payloadPalsu.$t");
cek('Payload diubah jadi admin (tanpa kunci) -> 401', $status == 401);

echo "\n3. OTORISASI: bolehkah kamu?  (budi = role user)\n";
list($status, $json) = panggil('GET', '/mhs', null, $tokenUser);
cek('user: GET /mhs -> 200 (boleh melihat)', $status == 200);

$baru = ['nim' => '99' . rand(100000, 999999), 'name' => 'Mahasiswa Uji', 'major' => 'Informatika'];
list($status, $json) = panggil('POST', '/mhs', $baru, $tokenUser);
cek('user: POST /mhs -> 403 (tidak boleh menambah)', $status == 403);

list($status, $json) = panggil('DELETE', '/mhs/1', null, $tokenUser);
cek('user: DELETE /mhs/1 -> 403', $status == 403);

list($status, $json) = panggil('GET', '/log', null, $tokenUser);
cek('user: GET /log -> 403', $status == 403);

echo "\n4. ADMIN boleh melakukan CRUD\n";
list($status, $json) = panggil('POST', '/mhs', $baru, $tokenAdmin);
cek('admin: POST /mhs -> 201', $status == 201);
$id = isset($json['id']) ? $json['id'] : 0;

list($status, $json) = panggil('POST', '/mhs', $baru, $tokenAdmin);
cek('admin: POST NIM kembar -> 409', $status == 409);

list($status, $json) = panggil('POST', '/mhs', ['nim' => 'abc'], $tokenAdmin);
cek('admin: POST data tidak valid -> 422', $status == 422);

$baru['name'] = 'Nama Diubah';
list($status, $json) = panggil('PUT', "/mhs/$id", $baru, $tokenAdmin);
cek('admin: PUT -> 200', $status == 200);

list($status, $json) = panggil('GET', '/mhs/' . rawurlencode('1 OR 1=1'), null, $tokenAdmin);
cek('admin: id "1 OR 1=1" -> 400 (validasi input)', $status == 400);

list($status, $json) = panggil('DELETE', "/mhs/$id", null, $tokenAdmin);
cek('admin: DELETE -> 200', $status == 200);

echo "\n5. RATE LIMITING: pembatasan percobaan login\n";
$penyerang = 'penyerang' . rand(1000, 9999);          // username acak agar tidak mengunci akun asli
$kode = [];
for ($i = 1; $i <= 7; $i++) {
    list($status, $json) = panggil('POST', '/login', ['username' => $penyerang, 'password' => 'tebak' . $i]);
    $kode[] = $status;
}
echo "   status 7 percobaan berturut-turut: " . implode(', ', $kode) . "\n";
cek('5 percobaan pertama ditolak 401', array_slice($kode, 0, 5) == [401, 401, 401, 401, 401]);
cek('Percobaan ke-6 dst diblokir 429 (Too Many Requests)', $kode[5] == 429 && $kode[6] == 429);

$tokenAdmin2 = login('admin', 'admin123');
cek('Akun asli (admin) tidak ikut terkunci', $tokenAdmin2 !== null);

echo "\n6. LOGGING: siapa melakukan apa\n";
list($status, $json) = panggil('GET', '/log', null, $tokenAdmin);
cek('admin: GET /log -> 200', $status == 200);
echo "   10 catatan log terakhir:\n";
$adaUser = false; $ada401 = false; $ada403 = false; $ada429 = false;
foreach ($json['data'] as $i => $b) {
    if ($i < 10) {
        printf("   %s  %-6s %-14s -> %d  user=%s\n", $b['waktu'], $b['method'], substr(basename($b['path']), 0, 14), $b['status'], $b['username'] ?? '-');
    }
}
// Cek lebih banyak baris langsung dari log 20 terakhir
foreach ($json['data'] as $b) {
    if ($b['username'] == 'admin') $adaUser = true;
    if ($b['status'] == 401) $ada401 = true;
    if ($b['status'] == 403) $ada403 = true;
    if ($b['status'] == 429) $ada429 = true;
}
cek('Log mencatat nama pengguna (kolom username)', $adaUser);
cek('Log mencatat percobaan ditolak (401 / 403 / 429)', $ada401 || $ada403 || $ada429);

// ---------------------------------------------------------------------
echo "\n7. REGISTER: POST /register (publik)\n";
$uniq = 'pelajar' . rand(1000, 9999);
list($status, $json) = panggil('POST', '/register', ['username' => $uniq, 'password' => 'password123']);
cek('Register akun baru -> 201', $status == 201 && $json['status'] == 'sukses');
$registerUser = $uniq;
$registerPass = 'password123';
// Response berisi kunci 'user' (bukan 'data'), role otomatis 'user'.
cek('Register mengembalikan role otomatis "user"', isset($json['user']) && $json['user']['role'] == 'user');

// Username kembar -> 409
list($status, $json) = panggil('POST', '/register', ['username' => $registerUser, 'password' => 'password123']);
cek('Register username kembar -> 409', $status == 409);

// Password terlalu pendek -> 422
list($status, $json) = panggil('POST', '/register', ['username' => 'siapa' . rand(100, 999), 'password' => '123']);
cek('Register password < 8 karakter -> 422', $status == 422);

// Input tidak lengkap -> 422
list($status, $json) = panggil('POST', '/register', ['username' => 'siapa' . rand(100, 999)]);
cek('Register tanpa password -> 422', $status == 422);

// Akun baru bisa login
$tokenBaru = login($registerUser, $registerPass);
cek('Akun terdaftar bisa login -> dapat token', $tokenBaru !== null);

echo "\n8. GANTI PASSWORD: PUT /me/password (perlu token)\n";
// Ganti password dengan password lama yang benar -> 200
list($status, $json) = panggil('PUT', '/me/password', ['password_lama' => $registerPass, 'password_baru' => 'password456'], $tokenBaru);
cek('Ganti password (lama benar) -> 200', $status == 200);

// Password lama salah -> 401
list($status, $json) = panggil('PUT', '/me/password', ['password_lama' => 'salah', 'password_baru' => 'password456'], $tokenBaru);
cek('Ganti password dengan password lama salah -> 401', $status == 401);

// Password baru terlalu pendek -> 422
list($status, $json) = panggil('PUT', '/me/password', ['password_lama' => 'password456', 'password_baru' => '123'], $tokenBaru);
cek('Ganti password baru < 8 karakter -> 422', $status == 422);

// Setelah ganti, login dengan password BARU harus sukses, password LAMA harus gagal
$tokenBaru2 = login($registerUser, 'password456');
cek('Setelah ganti, login dengan password baru -> sukses', $tokenBaru2 !== null);
list($status, $json) = panggil('POST', '/login', ['username' => $registerUser, 'password' => 'password456']);
$tokenLamaGagal = ($status == 200);
list($status, $json) = panggil('POST', '/login', ['username' => $registerUser, 'password' => 'password123']);
cek('Setelah ganti, login dengan password lama -> 401 (gagal)', $status == 401);

echo "\n9. ROLE DOSEN: boleh PUT, tidak boleh DELETE\n";
$tokenDosen = login('dosen', 'dosen123');
cek('Login dosen -> dapat token', $tokenDosen !== null);

// Dosen boleh PUT /mhs
$baruDosen = ['nim' => '98' . rand(100000, 999999), 'name' => 'Dosen Uji', 'major' => 'Pendidikan'];
list($status, $json) = panggil('POST', '/mhs', $baruDosen, $tokenAdmin);
$idDosen = isset($json['id']) ? $json['id'] : 0;
list($status, $json) = panggil('PUT', "/mhs/$idDosen", $baruDosen, $tokenDosen);
cek('dosen: PUT /mhs -> 200 (boleh)', $status == 200);

// Dosen tidak boleh POST /mhs (hanya admin)
list($status, $json) = panggil('POST', '/mhs', $baruDosen, $tokenDosen);
cek('dosen: POST /mhs -> 403 (tidak boleh)', $status == 403);

// Dosen tidak boleh DELETE /mhs (hanya admin)
list($status, $json) = panggil('DELETE', "/mhs/$idDosen", null, $tokenDosen);
cek('dosen: DELETE /mhs -> 403 (tidak boleh)', $status == 403);

// Dosen tidak boleh lihat /log (hanya admin)
list($status, $json) = panggil('GET', '/log', null, $tokenDosen);
cek('dosen: GET /log -> 403', $status == 403);

echo "\n10. ANALISIS LOG: GET /log-analisis (hanya admin)\n";
list($status, $json) = panggil('GET', '/log-analisis', null, $tokenAdmin);
cek('admin: GET /log-analisis -> 200', $status == 200);
cek('Analisis memuat 3 query (login_gagal_per_username, ip_terbanyak, error_per_hari)',
    isset($json['data']['login_gagal_per_username'])
    && isset($json['data']['ip_terbanyak'])
    && isset($json['data']['error_per_hari']));
// IP terbanyak minimal 1 baris (request yang sudah kita lakukan)
$adaIp = false;
foreach ($json['data']['ip_terbanyak'] as $row) {
    if (isset($row['ip']) && isset($row['jumlah'])) { $adaIp = true; break; }
}
cek('Analisis: ip_terbanyak berisi kolom ip dan jumlah', $adaIp);

// Non-admin tidak boleh akses /log-analisis
list($status, $json) = panggil('GET', '/log-analisis', null, $tokenUser);
cek('user: GET /log-analisis -> 403', $status == 403);

// ---------------------------------------------------------------------
$total = $lulus + $gagal;
echo "\nHASIL: $lulus dari $total pengujian lulus\n";
exit($gagal == 0 ? 0 : 1);
