// Variant 1: Direct SQLi string concatenation
app.get('/sqli-v1', (req, res) => {
  const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  db.query(query);
});

// Variant 2: SQLi template literal
app.get('/sqli-v2', (req, res) => {
  const query = `SELECT * FROM users WHERE username = '${req.query.username}'`;
  db.query(query);
});

// Variant 3: Parameterized query that uses concat (tricky safe)
app.get('/sqli-v3', (req, res) => {
  // Matches regex because of SELECT ... FROM ... + '?'
  const query = "SELECT * FROM users WHERE status = 'active' AND id = " + "?";
  db.query(query, [req.query.id]);
});

// Variant 4: SQLi in nested callbacks
app.get('/sqli-v4', (req, res) => {
  const id = req.query.id;
  getUserGroup(id, (err, group) => {
    db.query("SELECT * FROM roles WHERE group = '" + group + "'", (err, roles) => {
      res.json(roles);
    });
  });
});

// Variant 5: SQLi with multi-hop taint input (3 hops)
app.get('/sqli-v5', (req, res) => {
  const hop1 = req.body.username;
  const hop2 = hop1;
  const hop3 = hop2;
  db.query("SELECT * FROM users WHERE name = '" + hop3 + "'");
});