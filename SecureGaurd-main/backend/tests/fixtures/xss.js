const z = require('zod');
// Vulnerable XSS - Direct
app.get('/xss-direct', (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

// Vulnerable XSS - Indirect
app.get('/xss-indirect', (req, res) => {
  const name = req.body.name;
  res.send("Hello " + name);
});

// Safe XSS - Zod Validation
app.post('/xss-zod', (req, res) => {
  const schema = z.object({ name: z.string() });
  const val = schema.parse(req.body);
  res.send("Hello " + val.name);
});

// Safe XSS - dangerouslySetInnerHTML with DOMPurify sanitize
const React = require('react');
function UserProfile({ userInput }) {
  const cleanHtml = DOMPurify.sanitize(userInput);
  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}