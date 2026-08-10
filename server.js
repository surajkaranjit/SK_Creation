const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'suraj_creation_secret_key_2026'; // Change this in production

// Ensure uploads folder exists
if (!fs.existsSync('./public/uploads')) {
    fs.mkdirSync('./public/uploads', { recursive: true });
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// File Upload Engine Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, './public/uploads'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// Database Initialization
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error('Database Connection Error:', err);
    else console.log('Connected to SQLite Database.');
});

// Create Tables & Seed Default Admin
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        youtube_url TEXT,
        category TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        caption TEXT,
        category TEXT,
        description TEXT,
        image_url TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS inquiries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        phone TEXT,
        message TEXT,
        status TEXT DEFAULT 'New',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Seed default admin: admin / admin123
    db.get(`SELECT * FROM admins WHERE username = 'admin'`, (err, row) => {
        if (!row) {
            const hash = bcrypt.hashSync('admin123', 10);
            db.run(`INSERT INTO admins (username, password) VALUES ('admin', ?)`, [hash]);
            console.log('Default Admin Created: Username: admin | Password: admin123');
        }
    });
});

// Auth Middleware for Protected Routes
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access Denied: No Token Provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or Expired Token' });
        req.user = user;
        next();
    });
}

// --- ADMIN AUTH ROUTE ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM admins WHERE username = ?`, [username], (err, admin) => {
        if (err || !admin) return res.status(400).json({ error: 'User not found' });
        if (!bcrypt.compareSync(password, admin.password)) {
            return res.status(400).json({ error: 'Invalid password' });
        }
        const token = jwt.sign({ id: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token });
    });
});

// --- PUBLIC API ROUTES ---
app.get('/api/videos', (req, res) => {
    db.all(`SELECT * FROM videos ORDER BY id DESC`, [], (err, rows) => res.json(rows || []));
});

app.get('/api/photos', (req, res) => {
    db.all(`SELECT * FROM photos ORDER BY id DESC`, [], (err, rows) => res.json(rows || []));
});

app.post('/api/inquiries', (req, res) => {
    const { name, email, phone, message } = req.body;
    db.run(`INSERT INTO inquiries (name, email, phone, message) VALUES (?, ?, ?, ?)`,
        [name, email, phone, message],
        function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true, id: this.lastID });
        }
    );
});

// --- PROTECTED ADMIN ROUTES ---
// Videos CRUD
app.post('/api/admin/videos', authenticateToken, (req, res) => {
    const { title, youtube_url, category } = req.body;
    db.run(`INSERT INTO videos (title, youtube_url, category) VALUES (?, ?, ?)`,
        [title, youtube_url, category],
        function(err) { res.json({ success: true, id: this.lastID }); }
    );
});

app.delete('/api/admin/videos/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM videos WHERE id = ?`, [req.params.id], () => res.json({ success: true }));
});

// Photography CRUD
app.post('/api/admin/photos', authenticateToken, upload.single('image'), (req, res) => {
    const { caption, category, description } = req.body;
    const image_url = req.file ? `/uploads/${req.file.filename}` : '';
    db.run(`INSERT INTO photos (caption, category, description, image_url) VALUES (?, ?, ?, ?)`,
        [caption, category, description, image_url],
        function(err) { res.json({ success: true, id: this.lastID }); }
    );
});

app.delete('/api/admin/photos/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM photos WHERE id = ?`, [req.params.id], () => res.json({ success: true }));
});

// Inquiries Listing
app.get('/api/admin/inquiries', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM inquiries ORDER BY id DESC`, [], (err, rows) => res.json(rows || []));
});

// Admin Dashboard UI Route
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
