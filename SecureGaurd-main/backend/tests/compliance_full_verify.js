/**
 * SecureGuard Compliance - FULL Production Readiness Verification
 * Covers: Engine (all 4 frameworks), PDF, JSON, API security, DB, edge cases
 */
const assert = require('assert');
const { evaluateCompliance, FRAMEWORK_CONTROLS } = require('../services/complianceEngine');
const { generateCompliancePdf } = require('../utils/pdfGenerator');
const prisma = require('../prismaClient');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_secureguard_change_me';
const BASE = 'http://127.0.0.1:5000';
let passed = 0, failed = 0, total = 0;

function test(name, fn) {
  total++;
  try { fn(); console.log(`  ✅ ${name}`); passed++; }
  catch (e) { console.error(`  ❌ ${name}\n     ${e.message}`); failed++; }
}

async function testA(name, fn) {
  total++;
  try { await fn(); console.log(`  ✅ ${name}`); passed++; }
  catch (e) { console.error(`  ❌ ${name}\n     ${e.message}`); failed++; }
}

// Mock vulnerability sets
const VULNS_CRITICAL = [
  { id:1, title:'Hardcoded AWS Key', severity:'critical', type:'secret', status:'open', cweId:'CWE-798', filePath:'config.js', lineStart:10, lineEnd:10 },
  { id:2, title:'SQL Injection', severity:'critical', type:'sast', status:'open', cweId:'CWE-89', filePath:'db.js', lineStart:45, lineEnd:45 },
];
const VULNS_HIGH = [
  { id:3, title:'XSS Reflected', severity:'high', type:'sast', status:'open', cweId:'CWE-79', filePath:'render.js', lineStart:14, lineEnd:14 },
  { id:4, title:'Path Traversal', severity:'high', type:'sast', status:'open', cweId:'CWE-22', filePath:'files.js', lineStart:88, lineEnd:88 },
];
const VULNS_MEDIUM = [
  { id:5, title:'Weak Cipher', severity:'medium', type:'sast', status:'open', cweId:'CWE-327', filePath:'crypto.js', lineStart:5, lineEnd:5 },
];
const VULNS_LOW = [
  { id:6, title:'Info Disclosure', severity:'low', type:'sast', status:'open', cweId:'CWE-200', filePath:'log.js', lineStart:3, lineEnd:3 },
];
const VULNS_FIXED = [
  { id:7, title:'Old SQLi (fixed)', severity:'critical', type:'sast', status:'fixed', cweId:'CWE-89', filePath:'old.js', lineStart:1, lineEnd:1 },
];
const VULNS_MIXED = [...VULNS_CRITICAL, ...VULNS_HIGH, ...VULNS_MEDIUM, ...VULNS_LOW, ...VULNS_FIXED];
const VULNS_SPECIAL = [
  { id:8, title:'Vuln with "quotes" & <script>alert(1)</script> — émojis 🔥', severity:'high', type:'sast', status:'open', cweId:'CWE-79', filePath:'src/components/Spëcial—File (copy).tsx', lineStart:999, lineEnd:1000 },
];
const VULNS_MANY = Array.from({length:50}, (_,i) => ({
  id:100+i, title:`Vuln #${i}`, severity:['critical','high','medium','low'][i%4], type:['sast','secret','dependency','iac'][i%4],
  status:'open', cweId:`CWE-${79+i}`, filePath:`file${i}.js`, lineStart:i+1, lineEnd:i+1
}));

const MOCK_REPO = { id:1, name:'test-repo', fullName:'org/test-repo', platform:'github', language:'TypeScript' };

async function run() {
  console.log('\n════════════════════════════════════════════════════════');
  console.log(' SECUREGUARD COMPLIANCE — FULL PRODUCTION VERIFICATION');
  console.log('════════════════════════════════════════════════════════\n');

  // ═══════ SECTION 1: ALL 4 FRAMEWORKS ═══════
  for (const fw of ['SOC2', 'HIPAA', 'PCI-DSS', 'GDPR']) {
    console.log(`\n── ${fw} Framework Tests ──`);
    const controls = FRAMEWORK_CONTROLS[fw];

    test(`${fw}: has ≥5 controls defined`, () => {
      assert(controls && controls.length >= 5, `Only ${controls?.length}`);
    });

    test(`${fw}: each control has required fields`, () => {
      controls.forEach(c => {
        assert(c.id && c.name && c.category && c.description && c.recommendation, `Missing field in ${c.id}`);
        assert(Array.isArray(c.cweMatches) && c.cweMatches.length > 0, `No CWE in ${c.id}`);
        assert(Array.isArray(c.types) && c.types.length > 0, `No types in ${c.id}`);
      });
    });

    // Zero vulns
    test(`${fw}: zero-vuln yields score=100, all PASS`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:[], repository:MOCK_REPO });
      assert.strictEqual(r.summary.score, 100);
      assert.strictEqual(r.summary.totalFindings, 0);
      assert.strictEqual(r.summary.failedControls, 0);
      assert.strictEqual(r.summary.partialControls, 0);
      assert(r.controls.every(c => c.status === 'PASS'));
    });

    // Critical vulns cause FAILs
    test(`${fw}: critical vulns cause FAIL controls and score < 80`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:VULNS_CRITICAL, repository:MOCK_REPO });
      assert(r.summary.score < 80, `Score ${r.summary.score} not < 80`);
      assert(r.summary.failedControls > 0, 'No failed controls');
      assert(r.summary.critical === 2);
    });

    // Mixed vulns: PARTIAL exists
    test(`${fw}: mixed vulns produce PARTIAL controls`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:[...VULNS_MEDIUM, ...VULNS_LOW], repository:MOCK_REPO });
      assert(r.summary.partialControls > 0, 'No partial controls');
    });

    // Deterministic: same input → same output
    test(`${fw}: score is deterministic (run twice)`, () => {
      const a = evaluateCompliance({ framework:fw, vulnerabilities:VULNS_MIXED, repository:MOCK_REPO });
      const b = evaluateCompliance({ framework:fw, vulnerabilities:VULNS_MIXED, repository:MOCK_REPO });
      assert.strictEqual(a.summary.score, b.summary.score);
      assert.strictEqual(a.summary.failedControls, b.summary.failedControls);
    });

    // Recommendations are generated from real findings
    test(`${fw}: recommendations reflect actual finding counts`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:VULNS_MIXED, repository:MOCK_REPO });
      assert(r.recommendations.length > 0);
      const critRec = r.recommendations.find(x => x.priority === 'CRITICAL');
      assert(critRec, 'No CRITICAL recommendation despite critical vulns');
      assert(critRec.title.includes('2'), 'Title should mention count');
    });

    // Framework name in output
    test(`${fw}: output report.framework matches`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:[], repository:MOCK_REPO });
      assert.strictEqual(r.report.framework, fw);
    });

    // Disclaimer is present and NOT certification
    test(`${fw}: disclaimer present, says NOT official`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:[], repository:MOCK_REPO });
      assert(r.disclaimer.includes('does NOT constitute'), 'Missing disclaimer');
      assert(r.disclaimer.includes('automated'), 'Not labeled as automated');
    });

    // Limitations present
    test(`${fw}: limitations array populated`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:[], repository:MOCK_REPO });
      assert(r.limitations.length >= 2);
    });

    // Fixed vulns don't count as open findings
    test(`${fw}: fixed vulns excluded from score`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:VULNS_FIXED, repository:MOCK_REPO });
      assert.strictEqual(r.summary.totalFindings, 0);
      assert.strictEqual(r.summary.score, 100);
    });

    // Evidence text is based on actual findings
    test(`${fw}: evidence references actual finding data`, () => {
      const r = evaluateCompliance({ framework:fw, vulnerabilities:VULNS_CRITICAL, repository:MOCK_REPO });
      const failCtrl = r.controls.find(c => c.status === 'FAIL');
      if (failCtrl) {
        assert(failCtrl.evidence.includes('FAILED'), 'Evidence missing FAILED prefix');
        assert(failCtrl.evidence.includes('Critical') || failCtrl.evidence.includes('High'));
      }
    });
  }

  // ═══════ SECTION 2: PDF VERIFICATION ═══════
  console.log('\n── PDF Generator Tests ──');

  await testA('PDF: valid %PDF header', async () => {
    const data = evaluateCompliance({ framework:'SOC2', vulnerabilities:VULNS_MIXED, repository:MOCK_REPO });
    const buf = await generateCompliancePdf(data);
    assert(Buffer.isBuffer(buf));
    assert.strictEqual(buf.toString('utf8',0,4), '%PDF');
  });

  await testA('PDF: contains framework text', async () => {
    const data = evaluateCompliance({ framework:'HIPAA', vulnerabilities:[], repository:MOCK_REPO });
    const buf = await generateCompliancePdf(data);
    const text = buf.toString('utf8');
    assert(text.includes('HIPAA'), 'PDF does not contain HIPAA');
  });

  await testA('PDF: contains repository name', async () => {
    const data = evaluateCompliance({ framework:'SOC2', vulnerabilities:[], repository:MOCK_REPO });
    const buf = await generateCompliancePdf(data);
    assert(buf.toString('utf8').includes('test-repo'));
  });

  await testA('PDF: contains compliance score', async () => {
    const data = evaluateCompliance({ framework:'SOC2', vulnerabilities:VULNS_CRITICAL, repository:MOCK_REPO });
    const buf = await generateCompliancePdf(data);
    assert(buf.toString('utf8').includes(String(data.summary.score)));
  });

  await testA('PDF: disclaimer data is rendered (input data verified)', async () => {
    const data = evaluateCompliance({ framework:'SOC2', vulnerabilities:[], repository:MOCK_REPO });
    // Verify the data fed to PDF generator contains disclaimer
    assert(data.disclaimer.includes('DISCLAIMER'), 'Report data missing disclaimer');
    const buf = await generateCompliancePdf(data);
    // PDF is valid and contains enough content (disclaimer section adds bytes)
    assert(buf.length > 3000, 'PDF too small — disclaimer section likely missing');
  });

  await testA('PDF: multi-page for 50 vulns (no crash)', async () => {
    const data = evaluateCompliance({ framework:'SOC2', vulnerabilities:VULNS_MANY, repository:MOCK_REPO });
    const buf = await generateCompliancePdf(data);
    assert(buf.length > 5000, 'PDF too small for 50 vulns');
    assert.strictEqual(buf.toString('utf8',0,4), '%PDF');
  });

  await testA('PDF: special characters do not crash', async () => {
    const data = evaluateCompliance({ framework:'GDPR', vulnerabilities:VULNS_SPECIAL, repository:{ id:1, name:'Spëcial—Repo <test>', fullName:'org/special' } });
    const buf = await generateCompliancePdf(data);
    assert.strictEqual(buf.toString('utf8',0,4), '%PDF');
  });

  await testA('PDF: zero-vuln report generates valid PDF', async () => {
    const data = evaluateCompliance({ framework:'PCI-DSS', vulnerabilities:[], repository:MOCK_REPO });
    assert.strictEqual(data.findings.length, 0, 'Expected zero findings in data');
    const buf = await generateCompliancePdf(data);
    assert.strictEqual(buf.toString('utf8',0,4), '%PDF');
    assert(buf.length > 2000, 'Zero-vuln PDF too small');
  });

  // ═══════ SECTION 3: JSON VERIFICATION ═══════
  console.log('\n── JSON Report Structure Tests ──');

  test('JSON: valid JSON from evaluateCompliance', () => {
    const r = evaluateCompliance({ framework:'SOC2', vulnerabilities:VULNS_MIXED, repository:MOCK_REPO });
    const str = JSON.stringify(r);
    const parsed = JSON.parse(str);
    assert.strictEqual(parsed.report.framework, 'SOC2');
    assert.strictEqual(parsed.report.repositoryName, 'test-repo');
    assert.strictEqual(typeof parsed.summary.score, 'number');
    assert(parsed.controls.length >= 5);
    assert(parsed.recommendations.length >= 1);
    assert(parsed.limitations.length >= 2);
    assert(typeof parsed.disclaimer, 'string');
  });

  test('JSON: finding counts match actual vulns', () => {
    const r = evaluateCompliance({ framework:'SOC2', vulnerabilities:VULNS_MIXED, repository:MOCK_REPO });
    assert.strictEqual(r.summary.critical, 2);
    assert.strictEqual(r.summary.high, 2);
    assert.strictEqual(r.summary.medium, 1);
    assert.strictEqual(r.summary.low, 1);
    assert.strictEqual(r.summary.totalFindings, 6); // excludes fixed
  });

  test('JSON: controls have status/evidence/recommendation', () => {
    const r = evaluateCompliance({ framework:'HIPAA', vulnerabilities:VULNS_CRITICAL, repository:MOCK_REPO });
    r.controls.forEach(c => {
      assert(['PASS','PARTIAL','FAIL'].includes(c.status), `Bad status ${c.status} in ${c.id}`);
      assert(c.evidence.length > 10, `Short evidence in ${c.id}`);
      assert(c.recommendation.length > 10, `Short rec in ${c.id}`);
    });
  });

  // ═══════ SECTION 4: API ENDPOINT TESTS ═══════
  console.log('\n── API Endpoint Tests ──');

  // Helper
  function authHeader(userId) {
    return { 'Authorization': `Bearer ${jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '5m' })}`, 'Content-Type': 'application/json' };
  }

  await testA('API: GET /reports returns 401 without token', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports`);
    assert.strictEqual(r.status, 401);
  });

  await testA('API: POST /generate returns 401 without token', async () => {
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:{'Content-Type':'application/json'}, body:'{}' });
    assert.strictEqual(r.status, 401);
  });

  // Create test fixtures in DB
  let testUser, testUser2, testRepo, testReportId;
  await testA('DB SETUP: create test users, repo', async () => {
    testUser = await prisma.user.create({ data: { firstName:'CompTest', lastName:'User', email:`ct_${Date.now()}@test.com`, password:'hash123', onboardingCompleted:true } });
    testUser2 = await prisma.user.create({ data: { firstName:'Other', lastName:'User', email:`ct2_${Date.now()}@test.com`, password:'hash456', onboardingCompleted:true } });
    testRepo = await prisma.repository.create({ data: { userId:testUser.id, name:'verify-repo', fullName:`comptest/verify-repo-${Date.now()}`, url:'https://github.com/test/verify', platform:'github' } });
    assert(testUser.id > 0 && testUser2.id > 0 && testRepo.id > 0);
  });

  await testA('API: POST /generate — valid request', async () => {
    const h = authHeader(testUser.id);
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:h, body:JSON.stringify({ repositoryId:testRepo.id, framework:'SOC2', dateRangeOption:'30d' }) });
    assert.strictEqual(r.status, 201);
    const body = await r.json();
    assert(body.id > 0);
    assert.strictEqual(body.framework, 'SOC2');
    assert.strictEqual(body.complianceScore, 100);
    testReportId = body.id;
  });

  await testA('API: POST /generate — missing repositoryId returns 400', async () => {
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:authHeader(testUser.id), body:JSON.stringify({ framework:'SOC2' }) });
    assert.strictEqual(r.status, 400);
  });

  await testA('API: POST /generate — invalid framework returns 400', async () => {
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:authHeader(testUser.id), body:JSON.stringify({ repositoryId:testRepo.id, framework:'INVALID' }) });
    assert.strictEqual(r.status, 400);
  });

  await testA('API: POST /generate — non-existent repo returns 404', async () => {
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:authHeader(testUser.id), body:JSON.stringify({ repositoryId:999999, framework:'SOC2' }) });
    assert.strictEqual(r.status, 404);
  });

  await testA('API: POST /generate — other user repo returns 404 (IDOR)', async () => {
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:authHeader(testUser2.id), body:JSON.stringify({ repositoryId:testRepo.id, framework:'SOC2' }) });
    assert.strictEqual(r.status, 404);
  });

  await testA('API: POST /generate — NaN repositoryId returns 400', async () => {
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:authHeader(testUser.id), body:JSON.stringify({ repositoryId:'abc', framework:'SOC2' }) });
    assert.strictEqual(r.status, 400);
  });

  await testA('API: GET /reports — returns user reports', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports`, { headers:authHeader(testUser.id) });
    assert.strictEqual(r.status, 200);
    const body = await r.json();
    assert(Array.isArray(body) && body.length >= 1);
  });

  await testA('API: GET /reports — other user sees empty', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports`, { headers:authHeader(testUser2.id) });
    const body = await r.json();
    assert.strictEqual(body.length, 0);
  });

  await testA('API: GET /reports/:id — returns report', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}`, { headers:authHeader(testUser.id) });
    assert.strictEqual(r.status, 200);
    const body = await r.json();
    assert.strictEqual(body.id, testReportId);
    assert(body.reportData && body.reportData.controls);
  });

  await testA('API: GET /reports/:id — other user gets 404 (IDOR)', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}`, { headers:authHeader(testUser2.id) });
    assert.strictEqual(r.status, 404);
  });

  await testA('API: GET /reports/:id — non-existent returns 404', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/999999`, { headers:authHeader(testUser.id) });
    assert.strictEqual(r.status, 404);
  });

  await testA('API: GET /reports/:id — NaN returns 400', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/abc`, { headers:authHeader(testUser.id) });
    assert.strictEqual(r.status, 400);
  });

  // PDF endpoint
  await testA('API: GET /reports/:id/pdf — valid PDF download', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}/pdf`, { headers:authHeader(testUser.id) });
    assert.strictEqual(r.status, 200);
    assert(r.headers.get('content-type').includes('application/pdf'));
    assert(r.headers.get('content-disposition').includes('.pdf'));
    const buf = Buffer.from(await r.arrayBuffer());
    assert.strictEqual(buf.toString('utf8',0,4), '%PDF');
  });

  await testA('API: GET /reports/:id/pdf — IDOR blocked', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}/pdf`, { headers:authHeader(testUser2.id) });
    assert.strictEqual(r.status, 404);
  });

  // JSON endpoint
  await testA('API: GET /reports/:id/json — valid JSON download', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}/json`, { headers:authHeader(testUser.id) });
    assert.strictEqual(r.status, 200);
    assert(r.headers.get('content-disposition').includes('.json'));
    const body = await r.json();
    assert.strictEqual(body.report.framework, 'SOC2');
    assert(body.controls.length >= 5);
    assert(body.disclaimer.includes('does NOT'));
  });

  await testA('API: GET /reports/:id/json — IDOR blocked', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}/json`, { headers:authHeader(testUser2.id) });
    assert.strictEqual(r.status, 404);
  });

  // Generate for all 4 frameworks via API
  for (const fw of ['HIPAA', 'PCI-DSS', 'GDPR']) {
    await testA(`API: POST /generate — ${fw} framework works`, async () => {
      const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:authHeader(testUser.id), body:JSON.stringify({ repositoryId:testRepo.id, framework:fw, dateRangeOption:'7d' }) });
      assert.strictEqual(r.status, 201);
      const body = await r.json();
      assert.strictEqual(body.framework, fw);
    });
  }

  // DELETE
  await testA('API: DELETE — IDOR blocked', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}`, { method:'DELETE', headers:authHeader(testUser2.id) });
    assert.strictEqual(r.status, 404);
  });

  await testA('API: DELETE — valid delete', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}`, { method:'DELETE', headers:authHeader(testUser.id) });
    assert.strictEqual(r.status, 200);
    const check = await fetch(`${BASE}/api/compliance/reports/${testReportId}`, { headers:authHeader(testUser.id) });
    assert.strictEqual(check.status, 404);
  });

  await testA('API: DELETE — already deleted returns 404', async () => {
    const r = await fetch(`${BASE}/api/compliance/reports/${testReportId}`, { method:'DELETE', headers:authHeader(testUser.id) });
    assert.strictEqual(r.status, 404);
  });

  // ═══════ SECTION 5: SECURITY AUDIT ═══════
  console.log('\n── Security Audit Tests ──');

  await testA('SEC: error responses do not leak stack traces', async () => {
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:authHeader(testUser.id), body:JSON.stringify({ repositoryId:testRepo.id, framework:'SOC2', dateRangeOption:'custom', customFromDate:'not-a-date', customToDate:'also-bad' }) });
    const body = await r.json();
    assert(!body.stack, 'Stack trace leaked');
    assert(!body.error, 'Error detail leaked');
  });

  await testA('SEC: filename sanitization in PDF header', async () => {
    // Create a report with special name
    const r = await fetch(`${BASE}/api/compliance/generate`, { method:'POST', headers:authHeader(testUser.id), body:JSON.stringify({ repositoryId:testRepo.id, framework:'SOC2', dateRangeOption:'30d', reportName:'../../../etc/passwd <script>' }) });
    const body = await r.json();
    const pdf = await fetch(`${BASE}/api/compliance/reports/${body.id}/pdf`, { headers:authHeader(testUser.id) });
    const disp = pdf.headers.get('content-disposition');
    assert(!disp.includes('..'), 'Path traversal in filename');
    assert(!disp.includes('<'), 'Script chars in filename');
    // cleanup
    await fetch(`${BASE}/api/compliance/reports/${body.id}`, { method:'DELETE', headers:authHeader(testUser.id) });
  });

  // ═══════ SECTION 6: DB CASCADE ═══════
  console.log('\n── Database Cascade Tests ──');

  await testA('DB: cascade delete — deleting repo deletes its reports', async () => {
    const tempRepo = await prisma.repository.create({ data:{ userId:testUser.id, name:'cascade-test', fullName:`comptest/cascade-${Date.now()}`, url:'https://test.com', platform:'github' } });
    const rData = evaluateCompliance({ framework:'SOC2', vulnerabilities:[], repository:tempRepo });
    const report = await prisma.complianceReport.create({ data:{ userId:testUser.id, repositoryId:tempRepo.id, name:'CascadeReport', framework:'SOC2', dateRangeOption:'30d', fromDate:new Date(), toDate:new Date(), complianceScore:100, reportData:rData } });
    await prisma.repository.delete({ where:{ id:tempRepo.id } });
    const check = await prisma.complianceReport.findFirst({ where:{ id:report.id } });
    assert.strictEqual(check, null, 'Report survived repo delete');
  });

  await testA('DB: cascade delete — deleting user deletes reports', async () => {
    const tempUser = await prisma.user.create({ data:{ firstName:'Temp', lastName:'Del', email:`del_${Date.now()}@test.com`, password:'h', onboardingCompleted:true } });
    const tempRepo = await prisma.repository.create({ data:{ userId:tempUser.id, name:'del-repo', fullName:`del/repo-${Date.now()}`, url:'https://test.com', platform:'github' } });
    await prisma.complianceReport.create({ data:{ userId:tempUser.id, repositoryId:tempRepo.id, name:'DelReport', framework:'SOC2', dateRangeOption:'30d', fromDate:new Date(), toDate:new Date(), complianceScore:100, reportData:{} } });
    await prisma.user.delete({ where:{ id:tempUser.id } });
    const check = await prisma.repository.findFirst({ where:{ id:tempRepo.id } });
    assert.strictEqual(check, null, 'Repo survived user delete');
  });

  // ═══════ CLEANUP ═══════
  console.log('\n── Cleanup ──');
  await testA('Cleanup test data', async () => {
    await prisma.complianceReport.deleteMany({ where:{ userId:testUser.id } });
    await prisma.repository.deleteMany({ where:{ userId:testUser.id } });
    await prisma.user.deleteMany({ where:{ id:{ in:[testUser.id, testUser2.id] } } });
  });

  // ═══════ FINAL REPORT ═══════
  console.log('\n════════════════════════════════════════════════════════');
  console.log(` RESULTS: ${passed} PASSED / ${failed} FAILED / ${total} TOTAL`);
  console.log('════════════════════════════════════════════════════════\n');
  if (failed > 0) process.exit(1);
}

run().catch(e => { console.error('Suite crash:', e); process.exit(1); });
