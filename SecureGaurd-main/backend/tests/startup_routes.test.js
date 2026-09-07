const test = require('node:test');
const assert = require('node:assert/strict');

test('SBOM route module loads without an RBAC export error', () => {
  assert.doesNotThrow(() => {
    require('../routes/sboms');
  });
});