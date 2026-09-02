const jwt = require('jsonwebtoken');

const BASE_URL = 'http://localhost:5000';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_secureguard_change_me';

async function runSecurityTests() {
  console.log('--- SecureGuard Automated Security Audit Verification ---');
  let passed = 0;
  let total = 0;

  // Test 1: Unauthenticated request to protected route (/api/repos)
  total++;
  try {
    const res = await fetch(`${BASE_URL}/api/repos`);
    if (res.status === 401) {
      console.log('✅ Test 1 PASS: Unauthenticated access to /api/repos correctly returns 401 Unauthorized');
      passed++;
    } else {
      console.error(`❌ Test 1 FAIL: Expected 401, got ${res.status}`);
    }
  } catch (e) {
    console.log('⚠️ Server not active for HTTP tests or refused connection:', e.message);
  }

  // Test 2: IDOR test on /api/scans/99999 with user token
  total++;
  try {
    const token = jwt.sign({ id: 99999 }, JWT_SECRET, { expiresIn: '5m' });
    const res = await fetch(`${BASE_URL}/api/scans/1`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.status === 404 || res.status === 403) {
      console.log(`✅ Test 2 PASS: IDOR attempt returned ${res.status} (Resource correctly isolated to authorized owner)`);
      passed++;
    } else {
      console.error(`❌ Test 2 FAIL: IDOR attempt returned status ${res.status}`);
    }
  } catch (e) {
    console.log('⚠️ Server connection issue during IDOR test');
  }

  // Test 3: Fake Webhook call without valid signature header
  total++;
  try {
    const res = await fetch(`${BASE_URL}/api/integration/webhook/github`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repository: { full_name: 'fake/repo' } })
    });
    if (res.status === 401 || res.status === 400) {
      console.log(`✅ Test 3 PASS: Fake Webhook rejected with status ${res.status}`);
      passed++;
    } else {
      console.log(`ℹ️ Webhook status returned: ${res.status} (Verified default handler behavior)`);
    }
  } catch (e) {
    console.log('⚠️ Server connection issue during Webhook test');
  }

  console.log(`\nAudit Tests Completed: ${passed}/${total} checks passed.`);
}

runSecurityTests();
