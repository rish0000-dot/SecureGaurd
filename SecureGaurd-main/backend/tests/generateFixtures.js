const fs = require('fs');
const path = require('path');

const fixturesDir = path.join(__dirname, 'fixtures');
if (!fs.existsSync(fixturesDir)) {
  fs.mkdirSync(fixturesDir);
}

// Helper to write fixture file
function writeFixture(filename, content) {
  fs.writeFileSync(path.join(fixturesDir, filename), content.trim());
}

// 1. SQL Injection (SAST-001) Variants
writeFixture('sqli_variants.js', `
// Variant 1: Direct SQLi string concatenation
app.get('/sqli-v1', (req, res) => {
  const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  db.query(query);
});

// Variant 2: SQLi template literal
app.get('/sqli-v2', (req, res) => {
  const query = \`SELECT * FROM users WHERE username = '\${req.query.username}'\`;
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
`);

// 2. XSS (SAST-002) Variants
writeFixture('xss_variants.js', `
// Variant 1: Direct XSS innerHTML/res.send
app.get('/xss-v1', (req, res) => {
  res.send("<h1>Welcome " + req.query.name + "</h1>");
});

// Variant 2: Indirect XSS via body params
app.post('/xss-v2', (req, res) => {
  const content = req.body.content;
  res.send("<div>" + content + "</div>");
});

// Variant 3: React dangerouslySetInnerHTML without sanitizer
function BadComponent({ req }) {
  const html = req.query.html;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// Variant 4: React dangerouslySetInnerHTML with DOMPurify sanitize (Safe)
const DOMPurify = require('dompurify');
function GoodComponent({ req }) {
  const html = req.query.html;
  const clean = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// Variant 5: Custom Sanitizer wrapper (custom function name)
function myCustomEscaper(str) {
  return str.replace(/&/g, "&amp;");
}
app.get('/xss-v5', (req, res) => {
  const cleaned = myCustomEscaper(req.query.name);
  res.send("Hello " + cleaned);
});
`);

// 3. Path Traversal (SAST-003) Variants
writeFixture('path_variants.js', `
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
`);

// 4. Hardcoded Secrets (SEC-003) Variants
writeFixture('secrets_variants.js', `
// Variant 1: Real aws-like key
const aws_key = 'AKIA1234567890ABCDEF'; // triggers SEC-001

// Variant 2: Private key block
const pkey = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQE\\n-----END RSA PRIVATE KEY-----'; // triggers SEC-002

// Variant 3: Hardcoded config secret password
const password = 'superSecretProductionPassword123!'; // triggers SEC-003

// Variant 4: False-positive-like placeholder config (non-vulnerable)
const secretKey = 'placeholder_for_local_dev'; // triggers SEC-003 but confidence should be low
`);

// 5. Command Execution (SAST-005) Variants
writeFixture('cmd_variants.js', `
const { exec, spawn } = require('child_process');

// Variant 1: Direct child_process exec
app.get('/cmd-v1', (req, res) => {
  exec('ping -c 1 ' + req.query.ip);
});

// Variant 2: Indirect child_process spawn
app.get('/cmd-v2', (req, res) => {
  const args = req.body.args;
  spawn('sh', ['-c', args]);
});
`);

// 6. Tricky Edge Cases & Deep Taint Chains (4-5 hops)
writeFixture('tricky_cases.js', `
// Edge Case 1: Regex that looks like string concat SELECT FROM +
const regexPattern = /SELECT\\s+.*\\s+FROM\\s+.*\\+/i; 
const stringVal = "SELECT * FROM users WHERE name = '" + "admin'"; // No user input

// Edge Case 2: Deeply nested function chain (5 hops taint)
function level5(input) {
  db.query("SELECT * FROM logs WHERE msg = '" + input + "'");
}
function level4(input) { level5(input); }
function level3(input) { level4(input); }
function level2(input) { level3(input); }
function level1(input) { level2(input); }

app.get('/deep-taint', (req, res) => {
  const val = req.query.msg;
  level1(val);
});

// Edge Case 3: Sanitizer used in the wrong scope
const safeVal = escape(req.query.user); // In parent scope
function innerProcess() {
  // Uses raw input again in inner scope
  db.query("SELECT * FROM audit WHERE actor = '" + req.query.user + "'");
}

// Edge Case 4: Custom wrapper validation
const z = require('zod');
function validateInput(schema, payload) {
  return schema.safeParse(payload);
}
app.post('/validate-custom', (req, res) => {
  const schema = z.object({ id: z.number() });
  const result = validateInput(schema, req.body);
  res.send("Parsed: " + result.success);
});
`);

// 7. Mock test files to check Test File False Positives (at least 5 findings in here)
writeFixture('mock_sast.test.js', `
describe('SAST Unit Tests', () => {
  it('should test SQLi', () => {
    const q = "SELECT * FROM users WHERE username = '" + req.query.username + "'";
    db.query(q);
  });

  it('should test XSS', () => {
    res.send("<div>" + req.query.name + "</div>");
  });

  it('should test Command Execution', () => {
    const { exec } = require('child_process');
    exec('ping ' + req.query.ip);
  });

  it('should test Path Traversal', () => {
    const fs = require('fs');
    fs.readFile(req.query.file);
  });

  it('should test Secret matching', () => {
    const password = 'test_suite_dummy_password_constant';
  });
});
`);

console.log("Fixtures generated successfully inside backend/tests/fixtures/");
