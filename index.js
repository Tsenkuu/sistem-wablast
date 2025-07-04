// startup.js
// File ini berfungsi sebagai titik masuk awal aplikasi.
// Anda dapat menambahkan logika inisialisasi atau setup di sini
// sebelum aplikasi utama (server.js) dimulai.

console.log('Memulai proses startup aplikasi...');

// Mengambil port dari variabel lingkungan atau default ke 3000
const PORT_INTERNAL = process.env.PORT || 3000;
const EXTERNAL_IP = '160.191.77.60'; // IP eksternal yang Anda berikan
const EXTERNAL_PORT = '7851'; // Port eksternal yang Anda berikan

console.log(`Aplikasi ini diharapkan dapat diakses secara eksternal melalui: http://${EXTERNAL_IP}:${EXTERNAL_PORT}`);
console.log(`Pastikan variabel lingkungan PORT diatur ke ${EXTERNAL_PORT} di file .env Anda.`);
console.log(`Secara internal, aplikasi akan berjalan pada port: ${PORT_INTERNAL}`);


// Contoh logika startup (opsional):
// Anda bisa menambahkan pemeriksaan database, loading konfigurasi awal,
// atau inisialisasi modul lain di sini.
// Misalnya:
// const someConfig = require('./config/initial_config');
// console.log('Konfigurasi awal dimuat:', someConfig);

// Setelah semua inisialisasi selesai, jalankan aplikasi utama.
// Pastikan path ke server.js benar relatif terhadap startup.js.
require('./server.js');

console.log('Aplikasi utama (server.js) telah dimulai.');

