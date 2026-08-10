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
const JWT_SECRET = process.env.JWT_SECRET || 'suraj_creation_secret_key_2026';

// Ensure uploads directory exists inside public folder
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Global Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Multer Storage Engine Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Database Connection
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) console.error('Database Connection Error:', err);
    else console.log('Connected to SQLite Database.');
});

// Database Tables Setup & Admin Initialization
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

    // Default Admin Seeding: username: admin | password: admin123
    db.get(`SELECT * FROM admins WHERE username = 'admin'`, (err, row) => {
        if (!row) {
            const hash = bcrypt.hashSync('admin123', 10);
            db.run(`INSERT INTO admins (username, password) VALUES ('admin', ?)`, [hash]);
            console.log('Default Admin Created -> Username: admin | Password: admin123');
        }
    });
});

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access Denied: No Token Provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or Expired Token' });
        }
        req.user = user;
        next();
    });
}

// --- ADMIN AUTH ROUTE ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    db.get(`SELECT * FROM admins WHERE LOWER(username) = LOWER(?)`, [username.trim()], (err, admin) => {
        if (err || !admin) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        if (!bcrypt.compareSync(password, admin.password)) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: admin.id, username: admin.username },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({ token });
    });
});

// --- PUBLIC ROUTES ---
app.get('/api/videos', (req, res) => {
    db.all(`SELECT * FROM videos ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
    });
});

app.get('/api/photos', (req, res) => {
    db.all(`SELECT * FROM photos ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
    });
});

app.post('/api/inquiries', (req, res) => {
    const { name, email, phone, message } = req.body;
    if (!name || !email) {
        return res.status(400).json({ error: 'Name and email are required' });
    }

    db.run(
        `INSERT INTO inquiries (name, email, phone, message) VALUES (?, ?, ?, ?)`,
        [name, email, phone, message],
        function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ success: true, id: this.lastID });
        }
    );
});

// --- PROTECTED ADMIN ROUTES ---

// Manage Videos
app.post('/api/admin/videos', authenticateToken, (req, res) => {
    const { title, youtube_url, category } = req.body;
    if (!title || !youtube_url) {
        return res.status(400).json({ error: 'Title and YouTube URL are required' });
    }

    db.run(
        `INSERT INTO videos (title, youtube_url, category) VALUES (?, ?, ?)`,
        [title, youtube_url, category || 'General'],
        function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ success: true, id: this.lastID });
        }
    );
});

app.delete('/api/admin/videos/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM videos WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, deleted: this.changes });
    });
});

// Manage Photos (Guarded Against Empty Uploads)
app.post('/api/admin/photos', authenticateToken, upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No image file uploaded' });
    }

    const caption = req.body.caption || '';
    const category = req.body.category || 'General';
    const description = req.body.description || '';
    const image_url = `uploads/${req.file.filename}`;

    db.run(
        `INSERT INTO photos (caption, category, description, image_url) VALUES (?, ?, ?, ?)`,
        [caption, category, description, image_url],
        function(err) {
            if (err) {
                console.error('Database Insertion Error:', err);
                return res.status(500).json({ error: 'Failed to insert photo' });
            }
            res.status(201).json({
                success: true,
                id: this.lastID,
                caption,
                category,
                description,
                image_url
            });
        }
    );
});

app.delete('/api/admin/photos/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM photos WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, deleted: this.changes });
    });
});

// View Inquiries
app.get('/api/admin/inquiries', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM inquiries ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
    });
});

// Admin Dashboard UI Fallback
app.get('/admin', (req, res) => {
    const adminPath = path.join(__dirname, 'views', 'admin.html');
    if (fs.existsSync(adminPath)) {
        res.sendFile(adminPath);
    } else {
        res.status(404).send('Admin page template not found in /views/admin.html');
    }
});

// Start Express Server
app.listen(PORT, () => {
    console.log(`Server executing at http://localhost:${PORT}`);
});