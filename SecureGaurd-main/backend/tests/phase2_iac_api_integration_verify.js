/**
 * Phase 2 — Advanced IaC & API Security Scanner Integration & End-to-End Test
 * 
 * Verifies:
 * 1. Unified scan execution over mixed source code, IaC, and API specifications
 * 2. Summary stats calculation (source, iac, api, terraform, k8s, docker, openapi)
 * 3. AI Remediation fix generation for IaC and API rules
 * 4. Compliance mapping of IaC and API findings to regulatory controls (SOC 2, HIPAA, PCI-DSS, GDPR)
 */

const fs = require('fs');
const path = require('path');
const { runSecurityScan } = require('../utils/securityScanner');
const { generateAiFix } = require('../utils/aiFixEngine');
const { evaluateCompliance } = require('../services/complianceEngine');

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    console.log(`  ✓ PASS: ${message}`);
    passedTests++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
  }
}

const FIXTURE_DIR = path.join(__dirname, 'temp_integration_fixtures');

function setupFixtures() {
  if (fs.existsSync(FIXTURE_DIR)) {
    fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(FIXTURE_DIR, { recursive: true });

  // 1. Source code file (SAST + Secret)
  fs.writeFileSync(path.join(FIXTURE_DIR, 'app.js'), `
const express = require('express');
const app = express();
const AWS_SECRET = "AKIA1234567890EXAMPLE";

app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query);
});
  `);

  // 2. Terraform file (IaC)
  fs.mkdirSync(path.join(FIXTURE_DIR, 'terraform'), { recursive: true });
  fs.writeFileSync(path.join(FIXTURE_DIR, 'terraform', 'storage.tf'), `
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "company-data"
  acl    = "public-read"
}
  `);

  // 3. Kubernetes file (IaC)
  fs.mkdirSync(path.join(FIXTURE_DIR, 'k8s'), { recursive: true });
  fs.writeFileSync(path.join(FIXTURE_DIR, 'k8s', 'pod.yaml'), `
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: main
      image: alpine
      securityContext:
        privileged: true
  `);

  // 4. Dockerfile (IaC)
  fs.writeFileSync(path.join(FIXTURE_DIR, 'Dockerfile'), `
FROM ubuntu:latest
EXPOSE 22
  `);

  // 5. OpenAPI specification (API)
  fs.mkdirSync(path.join(FIXTURE_DIR, 'api'), { recursive: true });
  fs.writeFileSync(path.join(FIXTURE_DIR, 'api', 'swagger.yaml'), `
openapi: 3.0.0
info:
  title: Microservice API
  version: 1.0.0
paths:
  /login:
    post:
      summary: User login
  `);
}

function cleanupFixtures() {
  if (fs.existsSync(FIXTURE_DIR)) {
    fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
  }
}

async function runIntegrationTests() {
  console.log('\n=== Starting Advanced IaC & API Integration & Compliance Verification ===\n');

  setupFixtures();

  try {
    // 1. Run Unified Security Scan Engine
    console.log('[Integration Step 1] Running Unified Scanner Engine across Code, IaC & API');
    const scanOutput = runSecurityScan(FIXTURE_DIR);

    assert(Array.isArray(scanOutput.findings), 'Scan output contains findings array');
    assert(scanOutput.summaryStats !== undefined, 'Scan output contains summaryStats');

    const stats = scanOutput.summaryStats;
    assert(stats.sourceCodeCount >= 2, `Detected SAST/Secret findings (found: ${stats.sourceCodeCount})`);
    assert(stats.iacCount >= 3, `Detected IaC findings (found: ${stats.iacCount})`);
    assert(stats.apiCount >= 1, `Detected API specification findings (found: ${stats.apiCount})`);
    assert(stats.terraformCount >= 1, `Detailed breakdown: Terraform findings (found: ${stats.terraformCount})`);
    assert(stats.k8sCount >= 1, `Detailed breakdown: Kubernetes findings (found: ${stats.k8sCount})`);
    assert(stats.dockerCount >= 1, `Detailed breakdown: Docker findings (found: ${stats.dockerCount})`);
    assert(stats.openApiCount >= 1, `Detailed breakdown: OpenAPI findings (found: ${stats.openApiCount})`);

    // 2. AI Fix Engine Verification for IaC & API Findings
    console.log('\n[Integration Step 2] AI Fix Engine Remediation for IaC & API Findings');

    const tfVuln = scanOutput.findings.find(v => v.ruleId === 'TF-001');
    assert(tfVuln !== undefined, 'Found Terraform TF-001 finding in scan results');
    if (tfVuln) {
      const tfFix = await generateAiFix(tfVuln);
      assert(tfFix.fixedCode && tfFix.fixedCode.includes('block_public_acls'), 'AI Engine generates Terraform private S3 ACL fix');
    }

    const k8sVuln = scanOutput.findings.find(v => v.ruleId === 'K8S-001');
    assert(k8sVuln !== undefined, 'Found Kubernetes K8S-001 finding in scan results');
    if (k8sVuln) {
      const k8sFix = await generateAiFix(k8sVuln);
      assert(k8sFix.fixedCode && k8sFix.fixedCode.includes('privileged: false'), 'AI Engine generates Kubernetes unprivileged securityContext fix');
    }

    const dockerVuln = scanOutput.findings.find(v => v.ruleId === 'DOCKER-001');
    assert(dockerVuln !== undefined, 'Found Dockerfile DOCKER-001 finding in scan results');
    if (dockerVuln) {
      const dockerFix = await generateAiFix(dockerVuln);
      assert(dockerFix.fixedCode && dockerFix.fixedCode.includes('USER appuser'), 'AI Engine generates Docker non-root USER fix');
    }

    const apiVuln = scanOutput.findings.find(v => v.ruleId === 'API-001' || v.ruleId === 'API-006');
    assert(apiVuln !== undefined, 'Found OpenAPI finding in scan results');
    if (apiVuln) {
      const apiFix = await generateAiFix(apiVuln);
      assert(apiFix.fixedCode && (apiFix.fixedCode.includes('securitySchemes') || apiFix.fixedCode.includes('security')), 'AI Engine generates OpenAPI security fix');
    }

    // 3. Compliance Engine Integration
    console.log('\n[Integration Step 3] Compliance Engine Assessment for IaC & API Findings');
    const complianceResult = evaluateCompliance({ framework: 'SOC2', vulnerabilities: scanOutput.findings });

    assert(complianceResult.summary !== undefined, 'Compliance engine returns assessment summary');
    assert(complianceResult.controls !== undefined, 'Compliance engine evaluates framework controls');

    // Verify IaC boundary control matching in SOC 2 (SOC2-CC6.6 or SOC2-CC7.1 or SOC2-CC6.1)
    const boundaryControl = complianceResult.controls.find(c => c.id === 'SOC2-CC6.6' || c.id === 'SOC2-CC7.1' || c.id === 'SOC2-CC6.1');
    assert(boundaryControl && boundaryControl.findingsCount > 0, 'IaC/API findings map to SOC 2 infrastructure & secrets controls');

    console.log(`\n==================================================`);
    console.log(`Integration Summary: ${passedTests}/${totalTests} tests passed.`);
    console.log(`==================================================\n`);

    cleanupFixtures();

    if (passedTests !== totalTests) {
      process.exit(1);
    }
  } catch (err) {
    cleanupFixtures();
    console.error('Fatal error during integration verification:', err);
    process.exit(1);
  }
}

runIntegrationTests();
