const fs = require('fs');
const path = require('path');

// Variant 1: Direct path traversal readFile
app.get('/path-v1', (req, res) => {
  fs.readFile(req.query.file, 'utf8', (err, data) => { res.send(data); });
});

// Variant 2: Indirect path traversal with custom folder join
app.get('/path-v2', (req, res) => {
  const filename = req.body.filename;
  const target = path.join('/var/www/uploads', filename);
  fs.createReadStream(target);
});

// Variant 3: Safe path traversal using path.resolve and startsWith check
app.get('/path-v3', (req, res) => {
  const filename = req.query.file;
  const target = path.resolve('/safe/dir', filename);
  if (target.startsWith('/safe/dir')) {
    fs.readFile(target, 'utf8');
  }
});