/**
 * Phase 2 — Advanced IaC & API Security Scanner Unit Verification
 * 
 * Verifies detection logic across:
 * 1. Terraform (.tf, .tf.json)
 * 2. Kubernetes (.yaml, .yml)
 * 3. Dockerfile
 * 4. OpenAPI / Swagger specs (.yaml, .json)
 * 5. Input security & malformed input handling
 */

const fs = require('fs');
const path = require('path');
const { scanTerraformFile } = require('../utils/iacTerraformScanner');
const { scanKubernetesFile } = require('../utils/iacK8sScanner');
const { scanDockerfile } = require('../utils/iacDockerScanner');
const { scanAPISpecFile } = require('../utils/apiSpecScanner');
const { runSecurityScan } = require('../utils/securityScanner');

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

// Temporary directory for test fixtures
const FIXTURE_DIR = path.join(__dirname, 'temp_iac_fixtures');

function setupFixtures() {
  if (fs.existsSync(FIXTURE_DIR)) {
    fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(FIXTURE_DIR, { recursive: true });

  // 1. Vulnerable Terraform Fixture
  fs.writeFileSync(path.join(FIXTURE_DIR, 'main.tf'), `
resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "allow_ssh" {
  name = "allow_all"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin_all" {
  name   = "wildcard_policy"
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIA1234567890EXAMPLE"
  secret_key = "SecretPassword123!"
}
  `);

  // 2. Vulnerable Kubernetes Fixture
  fs.writeFileSync(path.join(FIXTURE_DIR, 'k8s_deploy.yaml'), `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  replicas: 1
  template:
    spec:
      hostNetwork: true
      hostPID: true
      volumes:
        - name: host-root
          hostPath:
            path: /
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            capabilities:
              add: ["SYS_ADMIN"]
          env:
            - name: DB_PASSWORD
              value: "PlaintextSecret123!"
  `);

  // 3. Vulnerable Dockerfile Fixture
  fs.writeFileSync(path.join(FIXTURE_DIR, 'Dockerfile'), `
FROM node:18
EXPOSE 22
ENV API_SECRET_KEY="supersecret123"
ADD http://example.com/script.sh /script.sh
RUN curl -sSL http://example.com/install.sh | sh
  `);

  // 4. Vulnerable OpenAPI Fixture
  fs.writeFileSync(path.join(FIXTURE_DIR, 'openapi.yaml'), `
openapi: 3.0.0
info:
  title: Vulnerable API
  version: 1.0.0
servers:
  - url: http://api.example.com/v1
paths:
  /admin/deleteUser:
    post:
      summary: Delete user
      security: []
      parameters:
        - name: access_token
          in: query
          required: true
          schema:
            type: string
  `);

  // 5. Malformed YAML Fixture (Security Robustness Test)
  fs.writeFileSync(path.join(FIXTURE_DIR, 'malformed.yaml'), `
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  containers:
    - name: test
      image: [unbalanced array declaration: {{ invalid
  `);
}

function cleanupFixtures() {
  if (fs.existsSync(FIXTURE_DIR)) {
    fs.rmSync(FIXTURE_DIR, { recursive: true, force: true });
  }
}

async function runTests() {
  console.log('\n=== Starting Advanced IaC & API Security Scanner Unit Verification ===\n');

  setupFixtures();

  try {
    // Test 1: Terraform Scanner Logic
    console.log('[Test Group 1] Terraform Static Security Analysis');
    const tfPath = path.join(FIXTURE_DIR, 'main.tf');
    const tfFindings = scanTerraformFile(tfPath, 'main.tf');

    const tfRuleIds = tfFindings.map(f => f.ruleId);
    assert(tfRuleIds.includes('TF-001'), 'Detects TF-001 (Public S3 Bucket ACL)');
    assert(tfRuleIds.includes('TF-002'), 'Detects TF-002 (Missing Storage Server-Side Encryption)');
    assert(tfRuleIds.includes('TF-003'), 'Detects TF-003 (Permissive Network Ingress 0.0.0.0/0)');
    assert(tfRuleIds.includes('TF-004'), 'Detects TF-004 (Wildcard IAM Policy)');
    assert(tfRuleIds.includes('TF-005'), 'Detects TF-005 (Hardcoded Provider Credentials)');

    const publicS3 = tfFindings.find(f => f.ruleId === 'TF-001');
    assert(publicS3 && publicS3.mlFeatures.framework === 'Terraform', 'Normalizes Terraform framework in mlFeatures');
    assert(publicS3 && publicS3.type === 'iac', 'Sets vulnerability type to "iac"');

    // Test 2: Kubernetes Scanner Logic
    console.log('\n[Test Group 2] Kubernetes Manifest Security Analysis');
    const k8sPath = path.join(FIXTURE_DIR, 'k8s_deploy.yaml');
    const k8sFindings = scanKubernetesFile(k8sPath, 'k8s_deploy.yaml');

    const k8sRuleIds = k8sFindings.map(f => f.ruleId);
    assert(k8sRuleIds.includes('K8S-001'), 'Detects K8S-001 (Privileged Container)');
    assert(k8sRuleIds.includes('K8S-002'), 'Detects K8S-002 (Container Running as Root / missing runAsNonRoot)');
    assert(k8sRuleIds.includes('K8S-003'), 'Detects K8S-003 (Host Network Exposure)');
    assert(k8sRuleIds.includes('K8S-004'), 'Detects K8S-004 (Host PID Exposure)');
    assert(k8sRuleIds.includes('K8S-005'), 'Detects K8S-005 (Dangerous HostPath Mount)');
    assert(k8sRuleIds.includes('K8S-006'), 'Detects K8S-006 (Missing Resource Limits)');
    assert(k8sRuleIds.includes('K8S-007'), 'Detects K8S-007 (Insecure Linux Capability SYS_ADMIN)');
    assert(k8sRuleIds.includes('K8S-008'), 'Detects K8S-008 (Allow Privilege Escalation)');
    assert(k8sRuleIds.includes('K8S-009'), 'Detects K8S-009 (Plaintext Password in ENV)');

    // Test 3: Dockerfile Scanner Logic
    console.log('\n[Test Group 3] Dockerfile Security Analysis');
    const dockerPath = path.join(FIXTURE_DIR, 'Dockerfile');
    const dockerFindings = scanDockerfile(dockerPath, 'Dockerfile');

    const dockerRuleIds = dockerFindings.map(f => f.ruleId);
    assert(dockerRuleIds.includes('DOCKER-001'), 'Detects DOCKER-001 (Missing USER instruction / Root Execution)');
    assert(dockerRuleIds.includes('DOCKER-002'), 'Detects DOCKER-002 (Exposed Port 22 SSH)');
    assert(dockerRuleIds.includes('DOCKER-003'), 'Detects DOCKER-003 (Hardcoded Secrets in ENV)');
    assert(dockerRuleIds.includes('DOCKER-004'), 'Detects DOCKER-004 (Risky ADD instruction)');
    assert(dockerRuleIds.includes('DOCKER-005'), 'Detects DOCKER-005 (Dangerous Remote Command Execution)');

    // Test 4: OpenAPI Spec Scanner Logic
    console.log('\n[Test Group 4] OpenAPI Specification Security Analysis');
    const apiPath = path.join(FIXTURE_DIR, 'openapi.yaml');
    const apiFindings = scanAPISpecFile(apiPath, 'openapi.yaml');

    const apiRuleIds = apiFindings.map(f => f.ruleId);
    assert(apiRuleIds.includes('API-001'), 'Detects API-001 (Missing Auth Requirement)');
    assert(apiRuleIds.includes('API-002'), 'Detects API-002 (Sensitive /admin Endpoint Without Security)');
    assert(apiRuleIds.includes('API-003'), 'Detects API-003 (Insecure HTTP Server Definition)');
    assert(apiRuleIds.includes('API-005'), 'Detects API-005 (Sensitive Parameter in Query String)');
    assert(apiRuleIds.includes('API-006'), 'Detects API-006 (Missing Global securitySchemes)');

    // Test 5: Malformed File Security & Robustness Check
    console.log('\n[Test Group 5] Safe Parsing & Malformed File Robustness');
    const malformedPath = path.join(FIXTURE_DIR, 'malformed.yaml');
    const malformedFindings = scanKubernetesFile(malformedPath, 'malformed.yaml');
    assert(Array.isArray(malformedFindings), 'Malformed YAML returns findings array without crashing');
    assert(malformedFindings.some(f => f.ruleId === 'K8S-PARSER-WARN'), 'Generates structured parser warning for malformed input');

    // Test 6: Unified Pipeline Execution Check
    console.log('\n[Test Group 6] Unified Security Scanner Pipeline Execution');
    const scanResult = runSecurityScan(FIXTURE_DIR);
    assert(scanResult.summaryStats.iacCount > 0, 'Unified scan output includes iacCount');
    assert(scanResult.summaryStats.apiCount > 0, 'Unified scan output includes apiCount');
    assert(scanResult.summaryStats.terraformCount > 0, 'Unified scan captures terraformCount');
    assert(scanResult.summaryStats.k8sCount > 0, 'Unified scan captures k8sCount');
    assert(scanResult.summaryStats.dockerCount > 0, 'Unified scan captures dockerCount');
    assert(scanResult.summaryStats.openApiCount > 0, 'Unified scan captures openApiCount');

    console.log(`\n==================================================`);
    console.log(`Verification Summary: ${passedTests}/${totalTests} tests passed.`);
    console.log(`==================================================\n`);

    cleanupFixtures();

    if (passedTests !== totalTests) {
      process.exit(1);
    }
  } catch (err) {
    cleanupFixtures();
    console.error('Fatal error during scanner verification:', err);
    process.exit(1);
  }
}

runTests();
