const babelParser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

const code1 = `
  const express = require('express');
  const app = express();
  app.get('/user', (req, res) => {
    const query = "SELECT * FROM users WHERE username = '" + req.query.username + "'";
    db.execute(query);
  });
`;

console.log("Original string lines:");
const lines = code1.split('\n');
lines.forEach((l, i) => console.log(`${i+1}: "${l}"`));

const ast = babelParser.parse(code1, { sourceType: 'unambiguous' });
traverse(ast, {
  enter(path) {
    if (path.node.loc) {
      console.log(path.node.type, 'line:', path.node.loc.start.line, 'to', path.node.loc.end.line);
    }
  }
});
