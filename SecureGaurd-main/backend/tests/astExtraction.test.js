const { extractASTFeatures } = require('../utils/astExtractor');
const assert = require('assert');

function runTests() {
  console.log("Running AST Feature Extraction Tests...");
  let passed = 0;
  let failed = 0;

  // Test 1: Vulnerable SQL Injection (String Concat)
  const code1 = `
    const express = require('express');
    const app = express();
    app.get('/user', (req, res) => {
      const query = "SELECT * FROM users WHERE username = '" + req.query.username + "'";
      db.execute(query);
    });
  `;
  const features1 = extractASTFeatures(code1, 'src/api.js', 'SAST-001', 5);
  try {
    assert.strictEqual(features1.is_string_concat, 1, "Failed: is_string_concat should be 1");
    assert.strictEqual(features1.is_parameterized_query, 0, "Failed: is_parameterized_query should be 0");
    assert.strictEqual(features1.is_user_input_direct, 1, "Failed: is_user_input_direct should be 1");
    assert.strictEqual(features1.has_sanitizer_nearby, 0, "Failed: has_sanitizer_nearby should be 0");
    passed++;
    console.log("✅ Test 1 (Vulnerable SQLi) Passed");
  } catch (e) {
    failed++;
    console.error("❌ Test 1 Failed:", e.message);
  }

  // Test 2: Safe Parameterized SQL Query
  const code2 = `
    const db = require('./db');
    app.post('/login', (req, res) => {
      const username = req.body.username;
      db.query("SELECT * FROM users WHERE username = ?", [username]);
    });
  `;
  const features2 = extractASTFeatures(code2, 'src/auth.js', 'SAST-001', 5);
  try {
    assert.strictEqual(features2.is_string_concat, 0, "Failed: is_string_concat should be 0");
    assert.strictEqual(features2.is_parameterized_query, 1, "Failed: is_parameterized_query should be 1");
    assert.strictEqual(features2.is_user_input_direct, 1, "Failed: is_user_input_direct should be 1");
    passed++;
    console.log("✅ Test 2 (Safe Parameterized SQLi) Passed");
  } catch (e) {
    failed++;
    console.error("❌ Test 2 Failed:", e.message);
  }

  // Test 3: Has Sanitizer Nearby
  const code3 = `
    import { escape } from 'validator';
    app.get('/search', (req, res) => {
      const q = escape(req.query.q);
      res.send("<div>" + q + "</div>");
    });
  `;
  const features3 = extractASTFeatures(code3, 'src/search.js', 'SAST-002', 5);
  try {
    assert.strictEqual(features3.has_sanitizer_nearby, 1, "Failed: has_sanitizer_nearby should be 1");
    assert.strictEqual(features3.is_string_concat, 1, "Failed: is_string_concat should be 1");
    passed++;
    console.log("✅ Test 3 (Sanitizer Nearby) Passed");
  } catch (e) {
    failed++;
    console.error("❌ Test 3 Failed:", e.message);
  }

  // Test 4: Has Type Validation (zod)
  const code4 = `
    const z = require('zod');
    const schema = z.object({ id: z.number() });
    app.post('/update', (req, res) => {
      const data = schema.parse(req.body);
    });
  `;
  const features4 = extractASTFeatures(code4, 'src/update.js', 'SAST-002', 5);
  try {
    assert.strictEqual(features4.has_type_validation, 1, "Failed: has_type_validation should be 1");
    passed++;
    console.log("✅ Test 4 (Type Validation) Passed");
  } catch (e) {
    failed++;
    console.error("❌ Test 4 Failed:", e.message);
  }

  console.log(`\nTests Completed: ${passed} passed, ${failed} failed.`);
  if (failed > 0) process.exit(1);
}

runTests();
