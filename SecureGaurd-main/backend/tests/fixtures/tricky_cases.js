// Edge Case 1: Regex that looks like string concat SELECT FROM +
const regexPattern = /SELECT\s+.*\s+FROM\s+.*\+/i; 
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