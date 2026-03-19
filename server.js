require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'wallet.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    google_id TEXT    NOT NULL UNIQUE,
    email     TEXT,
    name      TEXT,
    avatar    TEXT
  );
  CREATE TABLE IF NOT EXISTS expenses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    amount      REAL    NOT NULL,
    category    TEXT    NOT NULL,
    description TEXT,
    date        TEXT    NOT NULL,
    user_id     INTEGER REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS categories (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT    NOT NULL UNIQUE
  );
`);

// Migrations
try { db.exec('ALTER TABLE expenses ADD COLUMN user_id INTEGER REFERENCES users(id)'); } catch {}
try { db.exec('ALTER TABLE categories ADD COLUMN monthly_limit REAL DEFAULT NULL'); } catch {}

// Seed default categories
const seedCat = db.prepare('INSERT OR IGNORE INTO categories (name) VALUES (?)');
db.transaction(cats => cats.forEach(c => seedCat.run(c)))([
  'Food & Dining', 'Transport', 'Shopping', 'Housing',
  'Health', 'Entertainment', 'Education', 'Travel', 'Utilities', 'Other',
]);

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 },
}));
app.use(passport.initialize());
app.use(passport.session());

// ── Passport ─────────────────────────────────────────────────────────────────
passport.use(new GoogleStrategy(
  {
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  process.env.GOOGLE_CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`,
  },
  (_accessToken, _refreshToken, profile, done) => {
    db.prepare('INSERT OR IGNORE INTO users (google_id, email, name, avatar) VALUES (?, ?, ?, ?)')
      .run(profile.id, profile.emails?.[0]?.value || '', profile.displayName, profile.photos?.[0]?.value || '');
    db.prepare('UPDATE users SET name = ?, avatar = ?, email = ? WHERE google_id = ?')
      .run(profile.displayName, profile.photos?.[0]?.value || '', profile.emails?.[0]?.value || '', profile.id);
    const user = db.prepare('SELECT * FROM users WHERE google_id = ?').get(profile.id);
    done(null, user);
  },
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  done(null, user || false);
});

// ── Auth guard ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'], prompt: 'select_account' }),
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login.html' }),
  (_req, res) => res.redirect('/'),
);

app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/login.html');
    });
  });
});

app.get('/auth/me', requireAuth, (req, res) => {
  const { id, name, email, avatar } = req.user;
  res.json({ id, name, email, avatar });
});

// ── Static files (login.html is public) ──────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Categories API ────────────────────────────────────────────────────────────
app.get('/api/categories', requireAuth, (_req, res) => {
  res.json(db.prepare('SELECT * FROM categories ORDER BY name ASC').all());
});

app.post('/api/categories', requireAuth, (req, res) => {
  const { name, monthly_limit } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'name is required' });
  const limit = monthly_limit ? parseFloat(monthly_limit) : null;
  try {
    const result = db.prepare('INSERT INTO categories (name, monthly_limit) VALUES (?, ?)').run(name.trim(), limit);
    res.status(201).json({ id: result.lastInsertRowid, name: name.trim(), monthly_limit: limit });
  } catch {
    res.status(409).json({ error: 'Category already exists' });
  }
});

app.put('/api/categories/:id', requireAuth, (req, res) => {
  const { name, monthly_limit } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'name is required' });
  const limit = monthly_limit ? parseFloat(monthly_limit) : null;
  try {
    const result = db.prepare('UPDATE categories SET name = ?, monthly_limit = ? WHERE id = ?')
      .run(name.trim(), limit, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Category not found' });
    res.json({ id: Number(req.params.id), name: name.trim(), monthly_limit: limit });
  } catch {
    res.status(409).json({ error: 'Category already exists' });
  }
});

app.delete('/api/categories/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Category not found' });
  res.json({ success: true });
});

// ── Expenses API ──────────────────────────────────────────────────────────────
app.get('/api/expenses', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM expenses WHERE user_id = ? ORDER BY date DESC, id DESC').all(req.user.id));
});

app.post('/api/expenses', requireAuth, (req, res) => {
  const { amount, category, description, date } = req.body;
  if (!amount || !category || !date)
    return res.status(400).json({ error: 'amount, category, and date are required' });
  const result = db.prepare(
    'INSERT INTO expenses (amount, category, description, date, user_id) VALUES (?, ?, ?, ?, ?)',
  ).run(amount, category, description || '', date, req.user.id);
  res.status(201).json(db.prepare('SELECT * FROM expenses WHERE id = ?').get(result.lastInsertRowid));
});

app.delete('/api/expenses/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM expenses WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Expense not found' });
  res.json({ success: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`MyWallet running at http://localhost:${PORT}`));
