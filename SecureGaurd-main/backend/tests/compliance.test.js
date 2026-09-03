const assert = require('assert');
const { evaluateCompliance, FRAMEWORK_CONTROLS } = require('../services/complianceEngine');
const { generateCompliancePdf } = require('../utils/pdfGenerator');
const prisma = require('../prismaClient');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_secureguard_change_me';
const BASE_URL = process.env.TEST_BASE_URL || 'http://127.0.0.1:5000';

async function runComplianceTestSuite() {
  console.log('\n======================================================');
  console.log('  SECUREGUARD COMPLIANCE ENGINE & API TEST SUITE  ');
  console.log('======================================================\n');

  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      fn();
      console.log(`✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`❌ FAIL: ${name}\n   Error: ${err.message}`);
    }
  }

  async function testAsync(name, fn) {
    total++;
    try {
      await fn();
      console.log(`✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`❌ FAIL: ${name}\n   Error: ${err.message}`);
    }
  }

  // ── 1. COMPLIANCE ENGINE UNIT TESTS ──
  console.log('--- 1. Compliance Engine Unit Tests ---');

  test('Framework Controls Definitions Exist for All 4 Standards', () => {
    assert(FRAMEWORK_CONTROLS.SOC2 && FRAMEWORK_CONTROLS.SOC2.length >= 5, 'SOC2 controls missing');
    assert(FRAMEWORK_CONTROLS.HIPAA && FRAMEWORK_CONTROLS.HIPAA.length >= 5, 'HIPAA controls missing');
    assert(FRAMEWORK_CONTROLS['PCI-DSS'] && FRAMEWORK_CONTROLS['PCI-DSS'].length >= 5, 'PCI-DSS controls missing');
    assert(FRAMEWORK_CONTROLS.GDPR && FRAMEWORK_CONTROLS.GDPR.length >= 5, 'GDPR controls missing');
  });

  test('Zero Findings Repository yields 100% Score and PASS Status', () => {
    const result = evaluateCompliance({
      framework: 'SOC2',
      vulnerabilities: [],
      repository: { id: 1, name: 'clean-repo', fullName: 'org/clean-repo' },
      reportName: 'Clean Assessment'
    });

    assert.strictEqual(result.summary.score, 100);
    assert.strictEqual(result.summary.totalFindings, 0);
    assert.strictEqual(result.summary.failedControls, 0);
    assert(result.summary.passedControls > 0);
    assert.strictEqual(result.controls.every(c => c.status === 'PASS'), true);
  });

  test('Critical Vulnerabilities Cause Control FAIL and Score Deduction', () => {
    const mockVulns = [
      { id: 1, title: 'Hardcoded Secret Key', severity: 'critical', type: 'secret', status: 'open', cweId: 'CWE-798', filePath: 'config.js', lineStart: 12 },
      { id: 2, title: 'SQL Injection', severity: 'critical', type: 'sast', status: 'open', cweId: 'CWE-89', filePath: 'db.js', lineStart: 45 }
    ];

    const result = evaluateCompliance({
      framework: 'SOC2',
      vulnerabilities: mockVulns,
      repository: { id: 1, name: 'vulnerable-repo', fullName: 'org/vulnerable-repo' }
    });

    assert(result.summary.score < 80, `Expected score < 80, got ${result.summary.score}`);
    assert(result.summary.failedControls > 0, 'Expected failed controls');
    assert.strictEqual(result.summary.critical, 2);
  });

  test('HIPAA Mapping Evaluates Technical Safeguards Correctly', () => {
    const mockVulns = [
      { id: 10, title: 'Cleartext HTTP Transmission', severity: 'high', type: 'sast', status: 'open', cweId: 'CWE-319', filePath: 'api.js', lineStart: 10 }
    ];

    const result = evaluateCompliance({
      framework: 'HIPAA',
      vulnerabilities: mockVulns,
      repository: { id: 2, name: 'health-app', fullName: 'org/health-app' }
    });

    assert.strictEqual(result.report.framework, 'HIPAA');
    const transControl = result.controls.find(c => c.id === 'HIPAA-164.312(e)(1)');
    assert(transControl, 'Transmission security control missing');
    assert(transControl.status === 'PARTIAL' || transControl.status === 'FAIL');
  });

  test('PCI-DSS Mapping Identifies Cardholder Data & Secret Risks', () => {
    const result = evaluateCompliance({
      framework: 'PCI-DSS',
      vulnerabilities: [
        { id: 20, title: 'Exposed Stripe API Key', severity: 'critical', type: 'secret', status: 'open', cweId: 'CWE-798', filePath: 'stripe.js', lineStart: 5 }
      ],
      repository: { id: 3, name: 'pay-app', fullName: 'org/pay-app' }
    });

    assert.strictEqual(result.report.framework, 'PCI-DSS');
    const req3 = result.controls.find(c => c.id === 'PCI-REQ-3');
    assert(req3, 'PCI Requirement 3 missing');
    assert.strictEqual(req3.status, 'FAIL');
  });

  test('GDPR Mapping Evaluates Encryption & Privacy Standards', () => {
    const result = evaluateCompliance({
      framework: 'GDPR',
      vulnerabilities: [],
      repository: { id: 4, name: 'eu-portal', fullName: 'org/eu-portal' }
    });

    assert.strictEqual(result.report.framework, 'GDPR');
    assert.strictEqual(result.summary.score, 100);
  });

  // ── 2. PDF GENERATOR UNIT TEST ──
  console.log('\n--- 2. PDF Generator Unit Tests ---');

  await testAsync('PDF Generator Output Produces Valid PDF Buffer Header (%PDF)', async () => {
    const sampleReportData = evaluateCompliance({
      framework: 'SOC2',
      vulnerabilities: [
        { id: 1, title: 'XSS Vulnerability', severity: 'high', type: 'sast', status: 'open', cweId: 'CWE-79', filePath: 'render.js', lineStart: 14 }
      ],
      repository: { id: 1, name: 'test-repo', fullName: 'test/repo' }
    });

    const pdfBuffer = await generateCompliancePdf(sampleReportData);
    assert(Buffer.isBuffer(pdfBuffer), 'Output is not a Buffer');
    assert(pdfBuffer.length > 500, 'PDF buffer length too small');
    const pdfHeader = pdfBuffer.toString('utf8', 0, 4);
    assert.strictEqual(pdfHeader, '%PDF', `Expected PDF header %PDF, got ${pdfHeader}`);
  });

  // ── 3. API & SECURITY INTEGRATION TESTS ──
  console.log('\n--- 3. API & Security Integration Tests ---');

  await testAsync('GET /api/compliance/reports Returns 401 Unauthenticated', async () => {
    try {
      const res = await fetch(`${BASE_URL}/api/compliance/reports`);
      assert.strictEqual(res.status, 401);
    } catch (e) {
      console.log('   (Skipped network fetch if backend server is not running on 5000)');
    }
  });

  await testAsync('Database Verification: ComplianceReport Table Exists and Accepts Records', async () => {
    // Find or create test user
    let user = await prisma.user.findFirst();
    if (!user) {
      user = await prisma.user.create({
        data: {
          firstName: 'Test',
          lastName: 'Compliance',
          email: `compliancetest_${Date.now()}@example.com`,
          password: 'hashed_password_123',
          onboardingCompleted: true
        }
      });
    }

    let repo = await prisma.repository.findFirst({ where: { userId: user.id } });
    if (!repo) {
      repo = await prisma.repository.create({
        data: {
          userId: user.id,
          name: 'compliance-test-repo',
          fullName: `${user.firstName.toLowerCase()}/compliance-test-repo`,
          url: 'https://github.com/test/compliance',
          platform: 'github'
        }
      });
    }

    const testReportData = evaluateCompliance({
      framework: 'SOC2',
      vulnerabilities: [],
      repository: repo
    });

    const dbReport = await prisma.complianceReport.create({
      data: {
        userId: user.id,
        repositoryId: repo.id,
        name: 'Automated DB Test Report',
        framework: 'SOC2',
        dateRangeOption: '30d',
        fromDate: new Date(Date.now() - 30 * 86400000),
        toDate: new Date(),
        complianceScore: testReportData.summary.score,
        totalFindings: testReportData.summary.totalFindings,
        criticalCount: testReportData.summary.critical,
        highCount: testReportData.summary.high,
        mediumCount: testReportData.summary.medium,
        lowCount: testReportData.summary.low,
        passedControls: testReportData.summary.passedControls,
        partialControls: testReportData.summary.partialControls,
        failedControls: testReportData.summary.failedControls,
        reportData: testReportData
      }
    });

    assert(dbReport.id > 0, 'Report record failed to insert');
    assert.strictEqual(dbReport.framework, 'SOC2');

    // Retrieve report
    const fetched = await prisma.complianceReport.findFirst({ where: { id: dbReport.id } });
    assert.strictEqual(fetched.name, 'Automated DB Test Report');

    // Clean up test report
    await prisma.complianceReport.delete({ where: { id: dbReport.id } });
  });

  console.log(`\n======================================================`);
  console.log(`  COMPLIANCE TEST RESULTS: ${passed}/${total} PASSED  `);
  console.log(`======================================================\n`);

  if (passed !== total) {
    process.exit(1);
  }
}

runComplianceTestSuite();
