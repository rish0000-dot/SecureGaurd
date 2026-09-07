const test = require('node:test');
const assert = require('node:assert/strict');

const { getAllowedOrigins } = require('../config/cors');
const app = require('../server');

test('exports the Express app for serverless deployment', () => {
  assert.equal(typeof app, 'function');
  assert.equal(typeof app.get, 'function');
});

test('includes the configured frontend origin and local development origins', () => {
  const origins = getAllowedOrigins({
    FRONTEND_URL: 'https://secureguard-main.vercel.app'
  });

  assert.deepEqual(origins, [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'https://secureguard-main.vercel.app'
  ]);
});

test('does not add a blank or malformed frontend origin', () => {
  const origins = getAllowedOrigins({ FRONTEND_URL: 'not-a-url' });

  assert.equal(origins.includes(''), false);
  assert.equal(origins.includes('not-a-url'), false);
});
