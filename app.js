const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();
const db = require('./db');

const app = express();
const port = 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('uploads'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

function checkAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function checkAdmin(req, res, next) {
  if (req.session.user.role !== 'admin') return res.redirect('/dashboard');
  next();
}

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.query('INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
    [email, hashedPassword, role || 'user'],
    (err) => {
      if (err) return res.send('Error registering');
      res.redirect('/login');
    });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.send('Invalid login');
    const match = await bcrypt.compare(password, results[0].password);
    if (!match) return res.send('Invalid password');
    req.session.user = results[0];
    res.redirect('/dashboard');
  });
});

app.get('/dashboard', checkAuth, (req, res) => {
  if (req.session.user.role === 'admin') {
    db.query('SELECT files.*, users.email FROM files JOIN users ON files.user_id = users.id', (err, files) => {
      res.render('dashboard', { user: req.session.user, files });
    });
  } else {
    db.query('SELECT * FROM files WHERE user_id = ?', [req.session.user.id], (err, files) => {
      res.render('dashboard', { user: req.session.user, files });
    });
  }
});

app.post('/upload', checkAuth, upload.single('file'), (req, res) => {
  const file = req.file;
  const now = new Date();
  db.query('INSERT INTO files (user_id, filename, path, uploaded_at) VALUES (?, ?, ?, ?)',
    [req.session.user.id, file.originalname, file.filename, now], (err) => {
      if (err) return res.send('Upload error');
      res.redirect('/dashboard');
    });
});

app.get('/download/:id', checkAuth, (req, res) => {
  db.query('SELECT * FROM files WHERE id = ?', [req.params.id], (err, results) => {
    if (results.length === 0) return res.send('File not found');
    const file = results[0];
    if (req.session.user.role !== 'admin' && file.user_id !== req.session.user.id) return res.send('Access denied');
    res.download(path.join(__dirname, 'uploads', file.path));
  });
});

app.post('/delete/:id', checkAuth, (req, res) => {
  const fileId = req.params.id;
  db.query('SELECT * FROM files WHERE id = ?', [fileId], (err, results) => {
    if (results.length === 0) return res.send('File not found');
    const file = results[0];
    if (req.session.user.role !== 'admin' && file.user_id !== req.session.user.id) return res.send('Access denied');
    fs.unlink(path.join(__dirname, 'uploads', file.path), (err) => {
      db.query('DELETE FROM files WHERE id = ?', [fileId], () => {
        res.redirect('/dashboard');
      });
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
