// server.js - Aplikasi Utama Node.js Express

require('dotenv').config(); // Memuat variabel lingkungan dari .env
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const multer = require('multer'); // Untuk menangani upload file
const ExcelJS = require('exceljs'); // Untuk membaca/menulis Excel
const path = require('path');
const fs = require('fs'); // Untuk manajemen file sesi Baileys

// lowdb imports
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const lodash = require('lodash'); // Digunakan oleh lowdb untuk utilitas

// Import fungsi calculateSalary
const { calculateSalary } = require('./utils/salary');

// --- Konfigurasi Baileys ---
const { default: makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion, delay } = require('@whiskeysockets/baileys');
const { Boom } = require('@hapi/boom');
const pino = require('pino'); // Logger untuk Baileys
const qrcode = require('qrcode'); // Untuk menghasilkan QR code sebagai gambar

// Inisialisasi Express App
const app = express();
const PORT = process.env.PORT || 3000;

// --- Informasi Akses Eksternal (dari .env atau default) ---
// Ini adalah IP dan Port yang diharapkan untuk akses eksternal.
// Pastikan PORT di .env Anda sesuai dengan EXTERNAL_PORT jika Anda ingin mengaksesnya langsung.
const EXTERNAL_IP = '160.191.77.60'; // IP eksternal yang Anda berikan
const EXTERNAL_PORT = process.env.PORT || '7851'; // Menggunakan PORT dari .env atau default 7851

// --- Konfigurasi LowDB (Database JSON Berbasis File) ---
const file = path.join(__dirname, 'database.json');
const adapter = new JSONFile(file);
const db = new Low(adapter, { users: [], gaji_records: [] }); // Default data jika file kosong

// Memuat data dari file database.json
async function initializeDb() {
    await db.read();
    // Jika database baru atau kosong, inisialisasi dengan data default
    if (!db.data.users || db.data.users.length === 0) {
        // Hashing password 'password123' untuk user admin
        const hashedPassword = await bcrypt.hash('password123', 10);
        db.data.users.push({
            id: 1,
            username: 'admin',
            password: hashedPassword,
            role: 'admin',
            nomorhp: null,
            whatsapp_session_data: null,
            profile_picture_url: null // Tambahkan field untuk URL foto profil
        });
        await db.write(); // Simpan data inisial ke file
        console.log('Database inisialisasi dengan user admin.');
    }
}
initializeDb(); // Panggil fungsi inisialisasi database saat aplikasi dimulai

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Konfigurasi Session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Konfigurasi EJS sebagai View Engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Folder untuk file .ejs

// Middleware untuk menyajikan file statis dari folder 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Konfigurasi Multer untuk upload file (Excel dan Gambar)
const upload = multer({ dest: 'uploads/' }); // Folder sementara untuk file yang diupload

// Direktori untuk menyimpan foto profil
const PROFILE_PICTURES_DIR = path.join(__dirname, 'public', 'profile_pictures');
if (!fs.existsSync(PROFILE_PICTURES_DIR)) {
    fs.mkdirSync(PROFILE_PICTURES_DIR, { recursive: true });
}

// Konfigurasi Multer untuk upload foto profil
const profilePictureStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, PROFILE_PICTURES_DIR);
    },
    filename: (req, file, cb) => {
        // Gunakan ID user sebagai nama file untuk memastikan keunikan per user
        // Tambahkan timestamp untuk menghindari caching dan memastikan nama unik jika diupload berkali-kali
        const userId = req.session.userId;
        const ext = path.extname(file.originalname);
        cb(null, `profile_${userId}_${Date.now()}${ext}`);
    }
});
const uploadProfilePicture = multer({ storage: profilePictureStorage });


// --- Baileys Session Management ---
// Menyimpan sesi WhatsApp untuk setiap user_id
// Dalam produksi, ini harus disimpan di sistem file yang aman dan persisten
const WA_SESSIONS = {}; // { userId: { sock: WhatsAppSocket, authState: { creds, keys } } }

// Pastikan folder untuk sesi Baileys ada
const SESSIONS_DIR = './baileys_auth_sessions';
if (!fs.existsSync(SESSIONS_DIR)) {
    fs.mkdirSync(SESSIONS_DIR);
}

/**
 * Menginisialisasi koneksi WhatsApp untuk user tertentu.
 * @param {number} userId
 */
async function connectToWhatsApp(userId) {
    // Jika sesi sudah aktif, kembalikan saja
    if (WA_SESSIONS[userId] && WA_SESSIONS[userId].sock && WA_SESSIONS[userId].sock.user) {
        console.log(`[WA] Sesi aktif untuk user ${userId}.`);
        return WA_SESSIONS[userId].sock;
    }

    try {
        const { state, saveCreds } = await useMultiFileAuthState(`${SESSIONS_DIR}/${userId}`);
        const sock = makeWASocket({
            auth: state,
            printQRInTerminal: false, // Kita akan menangani QR code secara manual
            browser: ['Sistem Penggajian', 'Chrome', '1.0'],
            logger: pino({ level: 'silent' }) // Nonaktifkan log Baileys yang terlalu banyak
        });

        WA_SESSIONS[userId] = { sock, authState: state };

        sock.ev.on('connection.update', async (update) => {
            const { connection, lastDisconnect, qr } = update;

            // Cari user di database JSON
            const userIndex = db.data.users.findIndex(u => u.id === userId);
            if (userIndex === -1) {
                console.error(`[WA] User ${userId} tidak ditemukan di database.`);
                return;
            }

            if (qr) {
                // QR code tersedia, simpan ke database JSON
                console.log(`[WA] QR Code untuk user ${userId}:`, qr);
                const qrDataUri = await qrcode.toDataURL(qr);
                db.data.users[userIndex].whatsapp_session_data = {
                    qr_code_image: qrDataUri,
                    instance_id: userId,
                    token: 'dummy_token_baileys', // Token dummy karena Baileys tidak pakai token API
                    status: 'qr_available'
                };
                await db.write();
            }

            if (connection === 'open') {
                console.log(`[WA] Koneksi terbuka untuk user ${userId}`);
                // Perbarui status di database JSON
                db.data.users[userIndex].whatsapp_session_data = {
                    qr_code_image: null, // Hapus QR code setelah terhubung
                    instance_id: userId,
                    token: 'dummy_token_baileys',
                    status: 'connected'
                };
                await db.write();
            }

            if (connection === 'close') {
                let reason = new Boom(lastDisconnect?.error)?.output?.statusCode;
                console.log(`[WA] Koneksi tertutup untuk user ${userId}. Alasan: ${reason}`);

                // Perbarui status di database JSON
                db.data.users[userIndex].whatsapp_session_data = {
                    ...db.data.users[userIndex].whatsapp_session_data, // Pertahankan data lain
                    status: 'disconnected'
                };
                await db.write();

                if (reason === DisconnectReason.badSession || reason === DisconnectReason.logout) {
                    console.log(`[WA] Sesi buruk atau logout, hapus file sesi untuk user ${userId}`);
                    fs.rmSync(`${SESSIONS_DIR}/${userId}`, { recursive: true, force: true });
                    delete WA_SESSIONS[userId];
                    // Hapus juga dari database JSON
                    db.data.users[userIndex].whatsapp_session_data = null;
                    await db.write();
                } else if (reason === DisconnectReason.connectionClosed || reason === DisconnectReason.connectionLost || reason === DisconnectReason.restartRequired || reason === DisconnectReason.timedOut) {
                    console.log(`[WA] Mencoba menyambung ulang untuk user ${userId}...`);
                    await delay(5000); // Tunggu sebentar sebelum mencoba lagi
                    connectToWhatsApp(userId); // Coba reconnect
                } else if (reason === DisconnectReason.connectionReplaced) {
                    console.log(`[WA] Koneksi diganti untuk user ${userId}. Sesi baru dibuka di tempat lain. Hapus sesi ini.`);
                    fs.rmSync(`${SESSIONS_DIR}/${userId}`, { recursive: true, force: true });
                    delete WA_SESSIONS[userId];
                    db.data.users[userIndex].whatsapp_session_data = null;
                    await db.write();
                } else {
                    console.log(`[WA] Alasan putus koneksi tidak diketahui: ${reason}|${lastDisconnect.error}`);
                }
            }
        });

        sock.ev.on('creds.update', saveCreds); // Simpan kredensial saat ada pembaruan

        return sock;

    } catch (error) {
        console.error(`[WA] Gagal menyambung ke WhatsApp untuk user ${userId}:`, error);
        // Perbarui status di database JSON jika ada error
        const userIndex = db.data.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            db.data.users[userIndex].whatsapp_session_data = {
                ...db.data.users[userIndex].whatsapp_session_data,
                status: 'error',
                qr_code_image: null // Hapus QR code jika ada error koneksi
            };
            await db.write();
        }
        return null;
    }
}

/**
 * Fungsi untuk memeriksa status login.
 * @param {object} req - Objek request Express.
 * @param {object} res - Objek response Express.
 * @param {function} next - Fungsi middleware selanjutnya.
 */
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    next();
}

/**
 * Fungsi untuk memeriksa peran admin.
 * @param {object} req - Objek request Express.
 * @param {object} res - Objek response Express.
 * @param {function} next - Fungsi middleware selanjutnya.
 */
function requireAdmin(req, res, next) {
    if (!req.session.userId || req.session.role !== 'admin') {
        return res.status(403).render('error', { message: 'Anda tidak memiliki akses ke halaman ini.' });
    }
    next();
}

// --- ROUTES ---

// Route untuk halaman awal (redirect ke login)
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Route Login
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard');
    }
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        await db.read(); // Pastikan data terbaru dimuat
        const user = db.data.users.find(u => u.username === username);

        if (user) {
            if (await bcrypt.compare(password, user.password)) {
                req.session.userId = user.id;
                req.session.username = user.username;
                req.session.role = user.role;
                res.redirect('/dashboard');
            } else {
                res.render('login', { error: 'Password salah!' });
            }
        } else {
            res.render('login', { error: 'Username tidak ditemukan!' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.render('login', { error: 'Terjadi kesalahan server.' });
    }
});

// Route Registrasi
app.get('/register', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/dashboard'); // Jika sudah login, arahkan ke dashboard
    }
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    const { username, password, nomorhp } = req.body;

    if (!username || !password || !nomorhp) {
        return res.render('register', { error: 'Semua kolom harus diisi.' });
    }

    try {
        await db.read(); // Pastikan data terbaru dimuat
        const existingUser = db.data.users.find(u => u.username === username);
        if (existingUser) {
            return res.render('register', { error: 'Username sudah digunakan.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newId = (db.data.users.length > 0 ? Math.max(...db.data.users.map(u => u.id)) : 0) + 1;

        db.data.users.push({
            id: newId,
            username: username,
            password: hashedPassword,
            role: 'user', // Default role untuk registrasi adalah 'user'
            nomorhp: nomorhp,
            whatsapp_session_data: null,
            profile_picture_url: null // Tambahkan field untuk URL foto profil
        });
        await db.write();

        req.session.userId = newId;
        req.session.username = username;
        req.session.role = 'user';
        res.redirect('/dashboard'); // Langsung login setelah registrasi
    } catch (error) {
        console.error('Error during registration:', error);
        res.render('register', { error: 'Terjadi kesalahan saat pendaftaran.' });
    }
});


// Route Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/login');
    });
});

// Route Dashboard
app.get('/dashboard', requireLogin, async (req, res) => {
    try {
        await db.read(); // Pastikan data terbaru dimuat
        const gajiRecords = db.data.gaji_records.filter(record => record.user_id === req.session.userId);
        const currentUser = db.data.users.find(u => u.id === req.session.userId);

        let totalGaji = 0;
        let totalJam = 0;
        gajiRecords.forEach(record => {
            totalGaji += calculateSalary(record.jam_kerja, record.jenis_pekerjaan);
            totalJam += record.jam_kerja;
        });

        // Untuk riwayat pekerjaan terakhir (misal 5 terakhir)
        const recentRecords = lodash.orderBy(gajiRecords, ['tanggal'], ['desc']).slice(0, 5);
        const recentRecordsWithSalary = recentRecords.map(record => ({
            ...record,
            gaji: calculateSalary(record.jam_kerja, record.jenis_pekerjaan)
        }));

        res.render('dashboard', {
            username: req.session.username,
            role: req.session.role,
            totalPekerjaan: gajiRecords.length,
            totalJam: totalJam,
            totalGaji: totalGaji,
            recentRecords: recentRecordsWithSalary,
            currentUser: currentUser // Meneruskan data user saat ini untuk profil
        });
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        res.status(500).send('Terjadi kesalahan saat memuat dashboard.');
    }
});

// --- Route Edit Profil ---
app.get('/edit_profile', requireLogin, async (req, res) => {
    try {
        await db.read();
        const currentUser = db.data.users.find(u => u.id === req.session.userId);
        if (!currentUser) {
            return res.status(404).render('error', { message: 'User tidak ditemukan.' });
        }
        res.render('edit_profile', {
            username: req.session.username,
            role: req.session.role,
            currentUser: currentUser,
            message: req.session.message, // for success messages
            error: req.session.error // for error messages
        });
        req.session.message = null; // Clear messages after displaying
        req.session.error = null;
    } catch (error) {
        console.error('Error fetching edit profile page:', error);
        res.status(500).send('Terjadi kesalahan saat memuat halaman edit profil.');
    }
});

app.post('/edit_profile', requireLogin, async (req, res) => {
    const { username, nomorhp, new_password, current_password } = req.body;
    const userId = req.session.userId;

    try {
        await db.read();
        const userIndex = db.data.users.findIndex(u => u.id === userId);
        if (userIndex === -1) {
            req.session.error = 'User tidak ditemukan.';
            return res.redirect('/edit_profile');
        }

        const currentUser = db.data.users[userIndex];

        // Verifikasi password saat ini jika ada password baru atau perubahan username/nomorhp
        // Jika tidak ada password baru DAN username/nomorhp tidak berubah, tidak perlu verifikasi password
        if (new_password || username !== currentUser.username || nomorhp !== currentUser.nomorhp) {
            if (!current_password || !(await bcrypt.compare(current_password, currentUser.password))) {
                req.session.error = 'Password saat ini salah.';
                return res.redirect('/edit_profile');
            }
        }

        // Update username jika berubah dan tidak ada user lain dengan username yang sama
        if (username !== currentUser.username) {
            const existingUserWithNewUsername = db.data.users.find(u => u.username === username && u.id !== userId);
            if (existingUserWithNewUsername) {
                req.session.error = 'Username sudah digunakan oleh user lain.';
                return res.redirect('/edit_profile');
            }
            currentUser.username = username;
            req.session.username = username; // Update session username
        }

        // Update nomorhp
        currentUser.nomorhp = nomorhp;

        // Update password jika ada
        if (new_password) {
            currentUser.password = await bcrypt.hash(new_password, 10);
        }

        await db.write();
        req.session.message = 'Profil berhasil diperbarui!';
        res.redirect('/dashboard'); // Redirect ke dashboard setelah update
    } catch (error) {
        console.error('Error updating profile:', error);
        req.session.error = 'Terjadi kesalahan saat memperbarui profil: ' + error.message;
        res.redirect('/edit_profile');
    }
});

// --- Route Upload Foto Profil ---
app.get('/upload_profile_photo', requireLogin, async (req, res) => {
    try {
        await db.read();
        const currentUser = db.data.users.find(u => u.id === req.session.userId);
        if (!currentUser) {
            return res.status(404).render('error', { message: 'User tidak ditemukan.' });
        }
        res.render('upload_profile_photo', {
            username: req.session.username,
            role: req.session.role,
            currentUser: currentUser,
            message: req.session.message,
            error: req.session.error
        });
        req.session.message = null;
        req.session.error = null;
    } catch (error) {
        console.error('Error fetching upload profile photo page:', error);
        res.status(500).send('Terjadi kesalahan saat memuat halaman upload foto profil.');
    }
});

app.post('/api/upload_profile_photo', requireLogin, uploadProfilePicture.single('profile_picture'), async (req, res) => {
    const userId = req.session.userId;

    try {
        if (!req.file) {
            return res.status(400).json({ status: 'error', message: 'Tidak ada file yang diupload.' });
        }

        await db.read();
        const userIndex = db.data.users.findIndex(u => u.id === userId);
        if (userIndex === -1) {
            // Hapus file yang baru diupload jika user tidak ditemukan
            fs.unlinkSync(req.file.path);
            return res.status(404).json({ status: 'error', message: 'User tidak ditemukan.' });
        }

        const currentUser = db.data.users[userIndex];

        // Hapus foto profil lama jika ada
        if (currentUser.profile_picture_url) {
            const oldPath = path.join(__dirname, 'public', currentUser.profile_picture_url);
            if (fs.existsSync(oldPath)) {
                fs.unlinkSync(oldPath);
                console.log(`[Profile] Foto profil lama dihapus: ${oldPath}`);
            }
        }

        // Simpan path relatif ke database
        currentUser.profile_picture_url = `/profile_pictures/${req.file.filename}`;
        await db.write();

        res.json({ status: 'success', message: 'Foto profil berhasil diupload.', profile_picture_url: currentUser.profile_picture_url });
    } catch (error) {
        console.error('Error uploading profile picture:', error);
        // Hapus file yang baru diupload jika terjadi error
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ status: 'error', message: 'Terjadi kesalahan saat mengupload foto profil: ' + error.message });
    }
});


// --- Route Kelola Gaji (Admin Only) ---
app.get('/kelola_gaji', requireAdmin, async (req, res) => {
    try {
        await db.read(); // Pastikan data terbaru dimuat
        const users = db.data.users.map(u => ({ id: u.id, username: u.username }));
        const gajiRecords = db.data.gaji_records.map(record => {
            const user = db.data.users.find(u => u.id === record.user_id);
            return {
                ...record,
                username: user ? user.username : 'Unknown User',
                gaji: calculateSalary(record.jam_kerja, record.jenis_pekerjaan)
            };
        });
        const sortedGajiRecords = lodash.orderBy(gajiRecords, ['tanggal'], ['desc']);

        let editData = null;
        if (req.query.edit_salary_id) {
            editData = db.data.gaji_records.find(r => r.id === parseInt(req.query.edit_salary_id));
        }

        res.render('kelola_gaji', {
            username: req.session.username,
            role: req.session.role,
            users: users,
            gajiRecords: sortedGajiRecords,
            editData: editData
        });
    } catch (error) {
        console.error('Error fetching kelola_gaji data:', error);
        res.status(500).send('Terjadi kesalahan saat memuat halaman kelola gaji.');
    }
});

app.post('/kelola_gaji', requireAdmin, async (req, res) => {
    const { salary_id, user_id, nama, uraian, tanggal, jam_kerja, jenis_pekerjaan } = req.body;
    try {
        await db.read(); // Pastikan data terbaru dimuat
        if (salary_id) { // Edit mode
            const recordIndex = db.data.gaji_records.findIndex(r => r.id === parseInt(salary_id));
            if (recordIndex !== -1) {
                db.data.gaji_records[recordIndex] = {
                    ...db.data.gaji_records[recordIndex],
                    user_id: parseInt(user_id),
                    nama,
                    uraian,
                    tanggal,
                    jam_kerja: parseInt(jam_kerja),
                    jenis_pekerjaan
                };
            }
            req.session.message = 'Data gaji berhasil diperbarui!';
        } else { // Add mode
            const newId = (db.data.gaji_records.length > 0 ? Math.max(...db.data.gaji_records.map(r => r.id)) : 0) + 1;
            db.data.gaji_records.push({
                id: newId,
                user_id: parseInt(user_id),
                nama,
                uraian,
                tanggal,
                jam_kerja: parseInt(jam_kerja),
                jenis_pekerjaan,
                created_at: new Date().toISOString()
            });
            req.session.message = 'Data gaji berhasil ditambahkan!';
        }
        await db.write();
        res.redirect('/kelola_gaji');
    } catch (error) {
        console.error('Error saving gaji data:', error);
        req.session.error = 'Gagal menyimpan data gaji: ' + error.message;
        res.redirect('/kelola_gaji');
    }
});

app.get('/kelola_gaji/delete/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await db.read(); // Pastikan data terbaru dimuat
        db.data.gaji_records = db.data.gaji_records.filter(r => r.id !== parseInt(id));
        await db.write();
        req.session.message = 'Data gaji berhasil dihapus!';
        res.redirect('/kelola_gaji');
    } catch (error) {
        console.error('Error deleting gaji data:', error);
        req.session.error = 'Gagal menghapus data gaji: ' + error.message;
        res.redirect('/kelola_gaji');
    }
});


// --- Route Kelola User (Admin Only) ---
app.get('/kelola_user', requireAdmin, async (req, res) => {
    try {
        await db.read(); // Pastikan data terbaru dimuat
        const users = db.data.users.map(u => ({ id: u.id, username: u.username, role: u.role, nomorhp: u.nomorhp }));
        const sortedUsers = lodash.orderBy(users, ['role', 'username'], ['asc', 'asc']);

        let editUserData = null;
        if (req.query.edit_user_id) {
            editUserData = db.data.users.find(u => u.id === parseInt(req.query.edit_user_id));
            // Jangan kirim password hash ke frontend
            if (editUserData) {
                editUserData = { id: editUserData.id, username: editUserData.username, role: editUserData.role, nomorhp: editUserData.nomorhp };
            }
        }
        res.render('kelola_user', {
            username: req.session.username,
            role: req.session.role,
            users: sortedUsers,
            editUserData: editUserData
        });
    } catch (error) {
        console.error('Error fetching kelola_user data:', error);
        res.status(500).send('Terjadi kesalahan saat memuat halaman kelola user.');
    }
});

app.post('/kelola_user', requireAdmin, async (req, res) => {
    const { user_id, new_username, new_password, role, nomorhp } = req.body;
    try {
        await db.read(); // Pastikan data terbaru dimuat
        if (user_id) { // Edit mode
            const userIndex = db.data.users.findIndex(u => u.id === parseInt(user_id));
            if (userIndex !== -1) {
                db.data.users[userIndex].username = new_username;
                db.data.users[userIndex].role = role;
                db.data.users[userIndex].nomorhp = nomorhp; // Update nomorhp
                if (new_password) {
                    db.data.users[userIndex].password = await bcrypt.hash(new_password, 10);
                }
            }
            req.session.message = 'Data user berhasil diperbarui!';
        } else { // Add mode
            const newId = (db.data.users.length > 0 ? Math.max(...db.data.users.map(u => u.id)) : 0) + 1;
            const hashedPassword = await bcrypt.hash(new_password, 10);
            db.data.users.push({
                id: newId,
                username: new_username,
                password: hashedPassword,
                role: role,
                nomorhp: nomorhp, // Tambahkan nomorhp saat membuat user baru
                whatsapp_session_data: null,
                profile_picture_url: null // Tambahkan field untuk URL foto profil
            });
            req.session.message = 'User baru berhasil ditambahkan!';
        }
        await db.write();
        res.redirect('/kelola_user');
    } catch (error) {
        console.error('Error saving user data:', error);
        req.session.error = 'Gagal menyimpan data user: ' + error.message;
        res.redirect('/kelola_user');
    }
});

app.get('/kelola_user/delete/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await db.read(); // Pastikan data terbaru dimuat
        if (parseInt(id) === req.session.userId) {
            req.session.error = 'Anda tidak bisa menghapus akun Anda sendiri!';
        } else {
            const userToDelete = db.data.users.find(u => u.id === parseInt(id));
            if (userToDelete && userToDelete.profile_picture_url) {
                const photoPath = path.join(__dirname, 'public', userToDelete.profile_picture_url);
                if (fs.existsSync(photoPath)) {
                    fs.unlinkSync(photoPath);
                    console.log(`[Profile] Foto profil user ${id} dihapus: ${photoPath}`);
                }
            }
            db.data.users = db.data.users.filter(u => u.id !== parseInt(id));
            // Hapus juga gaji records yang terkait dengan user ini
            db.data.gaji_records = db.data.gaji_records.filter(r => r.user_id !== parseInt(id));
            await db.write();
            req.session.message = 'User berhasil dihapus!';
        }
        res.redirect('/kelola_user');
    } catch (error) {
        console.error('Error deleting user:', error);
        req.session.error = 'Gagal menghapus user: ' + error.message;
        res.redirect('/kelola_user');
    }
});

// --- Route Laporan (Admin & User) ---
app.get('/laporan', requireLogin, async (req, res) => {
    try {
        await db.read(); // Pastikan data terbaru dimuat
        const rekapGaji = db.data.users.map(user => {
            const userGajiRecords = db.data.gaji_records.filter(r => r.user_id === user.id);
            let totalGaji = 0;
            userGajiRecords.forEach(record => {
                totalGaji += calculateSalary(record.jam_kerja, record.jenis_pekerjaan);
            });
            return {
                username: user.username,
                jumlah_pekerjaan: userGajiRecords.length,
                total_gaji: totalGaji
            };
        });

        res.render('laporan', {
            username: req.session.username,
            role: req.session.role,
            rekapGaji: rekapGaji
        });
    } catch (error) {
        console.error('Error fetching laporan data:', error);
        res.status(500).send('Terjadi kesalahan saat memuat laporan.');
    }
});

// Endpoint untuk Export Excel (dari laporan)
app.post('/export_excel', requireLogin, async (req, res) => {
    try {
        await db.read(); // Pastikan data terbaru dimuat
        let records = db.data.gaji_records;
        console.log('[Export Excel] Total gaji_records di DB:', records.length); // Debug log

        if (req.session.role === 'user') {
            records = records.filter(r => r.user_id === req.session.userId);
            console.log(`[Export Excel] Records untuk user ${req.session.username} (ID: ${req.session.userId}):`, records.length); // Debug log
        }
        // Urutkan berdasarkan tanggal (opsional, sesuaikan kebutuhan)
        records = lodash.orderBy(records, ['tanggal'], ['desc']);

        if (records.length === 0) {
            console.log('[Export Excel] Tidak ada data untuk diekspor.');
            // Mengirim respons yang lebih informatif jika tidak ada data
            return res.status(200).send('<script>alert("Tidak ada data gaji untuk diekspor."); window.history.back();</script>');
        }

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Laporan Gaji');

        // Header kolom
        worksheet.columns = [
            { header: 'No', key: 'no', width: 5 },
            { header: 'Nama', key: 'nama', width: 20 },
            { header: 'Uraian', key: 'uraian', width: 30 },
            { header: 'Tanggal', key: 'tanggal', width: 15 },
            { header: 'Jam Kerja', key: 'jam_kerja', width: 15 },
            { header: 'Jenis Pekerjaan', key: 'jenis_pekerjaan', width: 20 },
            { header: 'Gaji', key: 'gaji', width: 15 }
        ];

        // Data baris
        records.forEach((record, index) => {
            const user = db.data.users.find(u => u.id === record.user_id);
            const rowData = {
                no: index + 1,
                nama: `${record.nama} (${user ? user.username : 'Unknown'})`,
                uraian: record.uraian,
                tanggal: record.tanggal,
                jam_kerja: record.jam_kerja,
                jenis_pekerjaan: record.jenis_pekerjaan,
                gaji: calculateSalary(record.jam_kerja, record.jenis_pekerjaan)
            };
            worksheet.addRow(rowData);
            console.log(`[Export Excel] Menambahkan baris:`, rowData); // Debug log
        });

        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 'attachment; filename=' + 'laporan_gaji.xlsx');

        await workbook.xlsx.write(res);
        res.end();
        console.log('[Export Excel] File Excel berhasil dikirim.'); // Debug log

    } catch (error) {
        console.error('Error exporting Excel:', error);
        res.status(500).send('Terjadi kesalahan saat mengekspor laporan Excel: ' + error.message); // Lebih detail
    }
});


// --- WhatsApp Integration (Baileys) ---

// Route untuk Tautkan Akun WA (User Only)
app.get('/wa_link', requireLogin, async (req, res) => {
    if (req.session.role !== 'user') {
        return res.status(403).render('error', { message: 'Halaman ini hanya untuk pengguna biasa.' });
    }

    try {
        await db.read(); // Pastikan data terbaru dimuat
        const user = db.data.users.find(u => u.id === req.session.userId);
        const sessionData = user ? user.whatsapp_session_data : null;

        let whatsappLinked = false;
        let qrCodeUrl = null;
        let qrCodeMessage = "QR Code akan muncul di sini setelah Anda mengklik tombol.";

        if (sessionData && sessionData.status === 'connected') {
            whatsappLinked = true;
            qrCodeMessage = "Akun WhatsApp Anda sudah tertaut!";
        } else if (sessionData && sessionData.qr_code_image) {
            qrCodeUrl = sessionData.qr_code_image;
            qrCodeMessage = "Silakan scan QR Code ini dengan aplikasi WhatsApp Anda.";
        }

        res.render('wa_link', {
            username: req.session.username,
            role: req.session.role,
            whatsappLinked: whatsappLinked,
            qrCodeUrl: qrCodeUrl,
            qrCodeMessage: qrCodeMessage
        });
    } catch (error) {
        console.error('Error fetching WA link data:', error);
        res.status(500).send('Terjadi kesalahan saat memuat halaman tautkan WA.');
    }
});

// API Endpoint untuk mendapatkan QR Code (dipanggil dari client-side atau form)
app.post('/api/whatsapp/connect', requireLogin, async (req, res) => {
    if (req.session.role !== 'user') {
        return res.status(403).json({ status: 'error', message: 'Hanya pengguna biasa yang dapat menautkan akun WhatsApp.' });
    }

    const userId = req.session.userId;
    try {
        await db.read(); // Pastikan data terbaru dimuat
        const user = db.data.users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json({ status: 'error', message: 'User tidak ditemukan.' });
        }

        const sock = await connectToWhatsApp(userId);
        if (sock && sock.user) { // Already connected
            return res.json({
                status: 'success',
                message: 'WhatsApp sudah terhubung.',
                qr_code_image: null, // Tidak perlu QR jika sudah terhubung
                instance_id: userId,
                token: 'dummy_token_baileys'
            });
        } else {
            // Jika belum terhubung, Baileys akan memancarkan event 'qr'
            // yang akan memperbarui database. Kita bisa langsung membaca dari database.
            const updatedUser = db.data.users.find(u => u.id === userId);
            const sessionData = updatedUser ? updatedUser.whatsapp_session_data : null;

            if (sessionData && sessionData.qr_code_image) {
                return res.json({
                    status: 'pending_qr',
                    message: 'QR Code sedang dibuat. Silakan refresh halaman atau tunggu.',
                    qr_code_image: sessionData.qr_code_image,
                    instance_id: userId,
                    token: 'dummy_token_baileys'
                });
            } else {
                return res.json({
                    status: 'processing',
                    message: 'Memulai koneksi WhatsApp. QR Code akan segera muncul.',
                    qr_code_image: null,
                    instance_id: userId,
                    token: 'dummy_token_baileys'
                });
            }
        }
    } catch (error) {
        console.error('Error connecting WhatsApp API:', error);
        res.status(500).json({ status: 'error', message: 'Gagal memulai koneksi WhatsApp.' });
    }
});

// API Endpoint untuk memutuskan tautan WhatsApp
app.post('/api/whatsapp/disconnect', requireLogin, async (req, res) => {
    if (req.session.role !== 'user') {
        return res.status(403).json({ status: 'error', message: 'Hanya pengguna biasa yang dapat memutuskan tautan akun WhatsApp.' });
    }

    const userId = req.session.userId;
    try {
        const sock = WA_SESSIONS[userId]?.sock;
        if (sock) {
            await sock.logout(); // Logout dari WhatsApp
            // File sesi akan dihapus oleh event 'connection.update'
            res.json({ status: 'success', message: 'Akun WhatsApp berhasil diputuskan tautannya.' });
        } else {
            // Jika tidak ada sesi aktif di memori, coba hapus file sesi dan database
            fs.rmSync(`${SESSIONS_DIR}/${userId}`, { recursive: true, force: true });
            const userIndex = db.data.users.findIndex(u => u.id === userId);
            if (userIndex !== -1) {
                db.data.users[userIndex].whatsapp_session_data = null;
                await db.write();
            }
            res.json({ status: 'success', message: 'Tidak ada sesi aktif, data sesi telah dibersihkan.' });
        }
    } catch (error) {
        console.error('Error disconnecting WhatsApp API:', error);
        res.status(500).json({ status: 'error', message: 'Gagal memutuskan tautan akun WhatsApp.' });
    }
});

// Route WA Blast (Admin & User)
app.get('/wa_blast', requireLogin, async (req, res) => {
    try {
        await db.read(); // Pastikan data terbaru dimuat
        const user = db.data.users.find(u => u.id === req.session.userId);
        const whatsappSessionData = user ? user.whatsapp_session_data : null;

        res.render('wa_blast', {
            username: req.session.username,
            role: req.session.role,
            whatsappSessionData: whatsappSessionData // Teruskan data sesi WA ke template
        });
    } catch (error) {
        console.error('Error fetching WA blast page:', error);
        res.status(500).send('Terjadi kesalahan saat memuat halaman WA Blast.');
    }
});

// API Endpoint untuk mengirim WA Blast (upload Excel dan Gambar)
// Menggunakan upload.fields untuk menangani multiple file inputs (excel_file dan image_file)
app.post('/api/whatsapp/blast', requireLogin, upload.fields([{ name: 'excel_file', maxCount: 1 }, { name: 'image_file', maxCount: 1 }]), async (req, res) => {
    const userId = req.session.userId;
    const messageTemplate = req.body.message_template;
    const startRow = parseInt(req.body.start_row) || 2; // Default mulai dari baris 2 (setelah header)
    const endRow = parseInt(req.body.end_row) || Infinity; // Default sampai akhir file

    const excelFile = req.files['excel_file'] ? req.files['excel_file'][0] : null;
    const imageFile = req.files['image_file'] ? req.files['image_file'][0] : null;

    if (!excelFile) {
        return res.status(400).json({ status: 'error', message: 'Mohon pilih file Excel.' });
    }

    try {
        await db.read(); // Pastikan data terbaru dimuat
        const user = db.data.users.find(u => u.id === userId);
        const sessionData = user ? user.whatsapp_session_data : null;

        if (!sessionData || sessionData.status !== 'connected') {
            // Hapus file yang diupload jika koneksi WA tidak aktif
            fs.unlinkSync(excelFile.path);
            if (imageFile) fs.unlinkSync(imageFile.path);
            return res.status(400).json({ status: 'error', message: 'Akun WhatsApp Anda belum tertaut atau tidak aktif. Silakan tautkan akun Anda terlebih dahulu.' });
        }

        const sock = WA_SESSIONS[userId]?.sock;
        if (!sock || !sock.user) {
            // Hapus file yang diupload jika sesi WhatsApp tidak valid
            fs.unlinkSync(excelFile.path);
            if (imageFile) fs.unlinkSync(imageFile.path);
            return res.status(400).json({ status: 'error', message: 'Sesi WhatsApp tidak aktif. Coba tautkan ulang akun.' });
        }

        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.readFile(excelFile.path);
        const worksheet = workbook.getWorksheet(1); // Ambil worksheet pertama

        let successCount = 0;
        let failCount = 0;
        const messagesToSend = [];

        // Baca gambar jika ada
        let imageBuffer = null;
        if (imageFile) {
            try {
                imageBuffer = fs.readFileSync(imageFile.path);
                console.log(`[WA Blast] Gambar '${imageFile.originalname}' berhasil dibaca.`);
            } catch (imgError) {
                console.error(`[WA Blast] Gagal membaca file gambar: ${imgError.message}`);
                // Lanjutkan tanpa gambar jika gagal membaca
            }
        }

        // Iterasi baris Excel sesuai rentang yang diminta
        worksheet.eachRow((row, rowNumber) => {
            // Lewati baris di luar rentang yang ditentukan
            if (rowNumber < startRow || rowNumber > endRow) {
                return;
            }
            // Lewati header jika startRow adalah 1 atau kurang (artinya baris 1 adalah header)
            if (rowNumber === 1 && startRow <= 1) return;

            let phoneNumber = row.getCell('E').text; // Kolom E untuk nomor telepon (misal: 08123..., 628123..., 8123...)
            const dataA = row.getCell('A').text;
            const dataB = row.getCell('B').text;
            const dataC = row.getCell('C').text;

            if (phoneNumber) {
                // Bersihkan nomor telepon dari karakter non-digit
                phoneNumber = phoneNumber.replace(/\D/g, '');

                // Logika untuk memformat nomor telepon agar sesuai dengan format JID WhatsApp
                if (phoneNumber.startsWith('08')) {
                    phoneNumber = '62' + phoneNumber.substring(1); // Ganti '08' menjadi '628'
                } else if (phoneNumber.startsWith('8') && phoneNumber.length > 5) { // Asumsi nomor Indonesia dimulai dengan 8 dan cukup panjang
                    phoneNumber = '62' + phoneNumber; // Tambahkan '62' di depan
                }
                // Jika sudah dimulai dengan '62', biarkan saja

                let finalMessage = messageTemplate
                    .replace(/{{A}}/g, dataA)
                    .replace(/{{B}}/g, dataB)
                    .replace(/{{C}}/g, dataC);

                messagesToSend.push({ to: phoneNumber, message: finalMessage });
            }
        });

        // Hapus file Excel dan Gambar setelah dibaca
        fs.unlinkSync(excelFile.path);
        if (imageFile) fs.unlinkSync(imageFile.path);

        console.log(`[WA Blast] Memulai pengiriman ke ${messagesToSend.length} nomor.`);

        for (const msg of messagesToSend) {
            try {
                const jid = `${msg.to}@s.whatsapp.net`; // Nomor sudah diformat di atas
                console.log(`[WA Blast] Mengirim pesan ke ${msg.to}...`);

                if (imageBuffer) {
                    await sock.sendMessage(jid, { image: imageBuffer, caption: msg.message });
                    console.log(`[WA Blast] Pesan dan gambar berhasil terkirim ke ${msg.to}.`);
                } else {
                    await sock.sendMessage(jid, { text: msg.message });
                    console.log(`[WA Blast] Pesan teks berhasil terkirim ke ${msg.to}.`);
                }
                successCount++;
                // Delay 20 detik antar pesan untuk menghindari rate limit
                await delay(20000);
            } catch (sendError) {
                console.error(`[WA Blast] Gagal mengirim ke ${msg.to}: ${sendError.message}`);
                failCount++;
            }
        }

        res.json({
            status: 'success',
            message: `Proses WA Blast selesai! Berhasil mengirim ke ${successCount} nomor. Gagal: ${failCount} nomor.`,
            success_count: successCount,
            fail_count: failCount
        });

    } catch (error) {
        console.error('Error processing WA blast:', error);
        // Pastikan file diupload dihapus jika ada error
        if (excelFile && fs.existsSync(excelFile.path)) {
            fs.unlinkSync(excelFile.path);
        }
        if (imageFile && fs.existsSync(imageFile.path)) {
            fs.unlinkSync(imageFile.path);
        }
        res.status(500).json({ status: 'error', message: 'Terjadi kesalahan saat memproses WA Blast: ' + error.message });
    }
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
    // Menambahkan log informasi akses eksternal di server.js
    console.log(`Aplikasi ini diharapkan dapat diakses secara eksternal melalui: http://${EXTERNAL_IP}:${EXTERNAL_PORT}`);
    console.log(`Pastikan variabel lingkungan PORT diatur ke ${EXTERNAL_PORT} di file .env Anda.`);
    console.log('Pastikan file database.json ada dan dapat diakses.');
});

// Tangani error yang tidak tertangkap
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Application specific logging, throwing an error, or other logic here
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    // Consider gracefully shutting down the server
    process.exit(1);
});
