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
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

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
    limits: { fileSize: 25 * 1024 * 1024 } // 25MB limit
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

    db.run(`CREATE TABLE IF NOT EXISTS gears (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT,
        name TEXT,
        specs TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS experiences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role TEXT,
        company TEXT,
        duration TEXT,
        description TEXT,
        logo TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS brands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        image_url TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS testimonials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        role TEXT,
        feedback TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS banner (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT
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
            { expiresIn: '24h' }
        );

        res.json({ token });
    });
});

// --- PUBLIC READ ROUTES ---
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

app.get('/api/gears', (req, res) => {
    db.all(`SELECT * FROM gears ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
    });
});

app.get('/api/experiences', (req, res) => {
    db.all(`SELECT * FROM experiences ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
    });
});

app.get('/api/brands', (req, res) => {
    db.all(`SELECT * FROM brands ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
    });
});

app.get('/api/testimonials', (req, res) => {
    db.all(`SELECT * FROM testimonials ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows || []);
    });
});

app.get('/api/banner', (req, res) => {
    db.get(`SELECT * FROM banner ORDER BY id DESC LIMIT 1`, [], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(row || {});
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

// --- ADMIN WRITE ROUTES (SUPPORTING BOTH /api/admin/* AND /api/*) ---

// 1. VIDEOS
const handleAddVideo = (req, res) => {
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
};
app.post('/api/admin/videos', authenticateToken, handleAddVideo);
app.post('/api/videos', authenticateToken, handleAddVideo);

app.delete('/api/admin/videos/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM videos WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, deleted: this.changes });
    });
});

// 2. PHOTOS
const handleAddPhoto = (req, res) => {
    const caption = req.body.caption || req.body.title || '';
    const category = req.body.category || 'General';
    const description = req.body.description || '';
    const image_url = req.file ? `uploads/${req.file.filename}` : (req.body.image_url || '');

    if (!image_url) {
        return res.status(400).json({ error: 'Image file or image_url is required' });
    }

    db.run(
        `INSERT INTO photos (caption, category, description, image_url) VALUES (?, ?, ?, ?)`,
        [caption, category, description, image_url],
        function(err) {
            if (err) return res.status(500).json({ error: 'Failed to insert photo' });
            res.status(201).json({ success: true, id: this.lastID, caption, category, description, image_url });
        }
    );
};
app.post('/api/admin/photos', authenticateToken, upload.single('image'), handleAddPhoto);
app.post('/api/photos', authenticateToken, upload.single('image'), handleAddPhoto);

app.delete('/api/admin/photos/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM photos WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, deleted: this.changes });
    });
});

// 3. GEARS
const handleAddGear = (req, res) => {
    const { category, name, specs } = req.body;
    if (!name) return res.status(400).json({ error: 'Gear name is required' });

    db.run(
        `INSERT INTO gears (category, name, specs) VALUES (?, ?, ?)`,
        [category || 'General', name, specs || ''],
        function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ success: true, id: this.lastID });
        }
    );
};
app.post('/api/admin/gears', authenticateToken, handleAddGear);
app.post('/api/gears', authenticateToken, handleAddGear);

app.delete('/api/admin/gears/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM gears WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, deleted: this.changes });
    });
});

// 4. EXPERIENCES
const handleAddExperience = (req, res) => {
    const { role, company, duration, description } = req.body;
    const logo = req.file ? `uploads/${req.file.filename}` : (req.body.logo || '');

    if (!role || !company) return res.status(400).json({ error: 'Role and Company are required' });

    db.run(
        `INSERT INTO experiences (role, company, duration, description, logo) VALUES (?, ?, ?, ?, ?)`,
        [role, company, duration || '', description || '', logo],
        function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ success: true, id: this.lastID });
        }
    );
};
app.post('/api/admin/experiences', authenticateToken, upload.single('logo'), handleAddExperience);
app.post('/api/experiences', authenticateToken, upload.single('logo'), handleAddExperience);

// 5. BRANDS
const handleAddBrand = (req, res) => {
    const name = req.body.name || '';
    const image_url = req.file ? `uploads/${req.file.filename}` : (req.body.image_url || '');

    db.run(
        `INSERT INTO brands (name, image_url) VALUES (?, ?)`,
        [name, image_url],
        function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ success: true, id: this.lastID });
        }
    );
};
app.post('/api/admin/brands', authenticateToken, upload.single('image'), handleAddBrand);
app.post('/api/brands', authenticateToken, upload.single('image'), handleAddBrand);

// 6. TESTIMONIALS
const handleAddTestimonial = (req, res) => {
    const { name, role, feedback } = req.body;
    if (!feedback) return res.status(400).json({ error: 'Feedback is required' });

    db.run(
        `INSERT INTO testimonials (name, role, feedback) VALUES (?, ?, ?)`,
        [name || 'Anonymous', role || 'Client', feedback],
        function(err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ success: true, id: this.lastID });
        }
    );
};
app.post('/api/admin/testimonials', authenticateToken, handleAddTestimonial);
app.post('/api/testimonials', authenticateToken, handleAddTestimonial);

// 7. BANNER
const handleAddBanner = (req, res) => {
    const url = req.file ? `uploads/${req.file.filename}` : req.body.url;
    if (!url) return res.status(400).json({ error: 'Banner URL or video file is required' });

    db.run(`INSERT INTO banner (url) VALUES (?)`, [url], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.status(201).json({ success: true, id: this.lastID, url });
    });
};
app.post('/api/admin/banner', authenticateToken, upload.single('banner'), handleAddBanner);
app.post('/api/banner', authenticateToken, upload.single('banner'), handleAddBanner);

// VIEW INQUIRIES
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