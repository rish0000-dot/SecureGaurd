const db = require('./db');
// Vulnerable SQLi - Direct
app.get('/user-direct', (req, res) => {
  db.query("SELECT * FROM users WHERE id = '" + req.query.id + "'");
});

// Vulnerable SQLi - Indirect
app.get('/user-indirect', (req, res) => {
  const uid = req.query.id;
  db.query("SELECT * FROM users WHERE id = '" + uid + "'");
});

// Safe SQLi - Parameterized
app.get('/user-safe', (req, res) => {
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
});

// Safe SQLi - Sanitized
app.get('/user-sanitized', (req, res) => {
  const clean = escape(req.query.id);
  db.query("SELECT * FROM users WHERE id = '" + clean + "'");
});