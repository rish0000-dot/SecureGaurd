const fs = require('fs');
const path = require('path');

// Vulnerable Path Traversal - Direct
app.get('/file-direct', (req, res) => {
  fs.readFileSync(path.join('/uploads', req.query.file));
});

// Vulnerable Path Traversal - Indirect
app.get('/file-indirect', (req, res) => {
  const f = req.body.file;
  fs.readFileSync(path.join('/uploads', f));
});