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