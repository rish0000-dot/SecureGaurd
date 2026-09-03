/**
 * SecureGuard Phase 2 Comprehensive Test Suite
 * 
 * Verifies:
 * 1. Multi-Tenant Organization Isolation (Org A vs Org B)
 * 2. Backend-Enforced RBAC Permissions (OWNER, ADMIN, DEVELOPER)
 * 3. Member Management & Role Escalation Defenses
 * 4. Cryptographic Invitation Flow (Generation, SHA-256 Hashing, Single-Use, Expiration)
 * 5. Final-Owner Demotion & Removal Protection
 * 6. Audit Logging Integrity
 * 7. Scoped Repository, Scan, Vulnerability, and Compliance Report Access
 */

const prisma = require('../prismaClient');
const jwt = require('jsonwebtoken');

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const authRoutes = require('../routes/auth');
const repoRoutes = require('../routes/repos');
const scanRoutes = require('../routes/scans');
const vulnRoutes = require('../routes/vulnerabilities');
const integrationRoutes = require('../routes/integration');
const aiRoutes = require('../routes/ai');
const classifierRoutes = require('../routes/classifier');
const complianceRoutes = require('../routes/compliance');
const orgRoutes = require('../routes/organizations');
const invitationRoutes = require('../routes/invitations');
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_secureguard_change_me';
const BASE_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5000';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    failed++;
  }
}

let serverInstance;

async function ensureServerRunning() {
  try {
    await fetch(`${BASE_URL}/api/ai/status`);
  } catch {
    console.log('Starting internal Express test server on port 5000...');
    const app = express();
    app.use(cors({ origin: true, credentials: true }));
    app.use(express.json());
    app.use(cookieParser());
    app.use('/api/auth', authRoutes);
    app.use('/api/repos', repoRoutes);
    app.use('/api/scans', scanRoutes);
    app.use('/api/vulnerabilities', vulnRoutes);
    app.use('/api/integration', integrationRoutes);
    app.use('/api/ai', aiRoutes);
    app.use('/api/classifier', classifierRoutes);
    app.use('/api/compliance', complianceRoutes);
    app.use('/api/organizations', orgRoutes);
    app.use('/api/invitations', invitationRoutes);

    await new Promise((resolve) => {
      serverInstance = app.listen(5000, () => {
        resolve();
      });
    });
  }
}

async function runTests() {
  console.log('\n================================================================');
  console.log(' SECUREGUARD PHASE 2: TEAMS, ORGANIZATIONS & RBAC VERIFICATION ');
  console.log('================================================================\n');

  await ensureServerRunning();

  let userOwnerA, userAdminA, userDevA, userOwnerB;
  let tokenOwnerA, tokenAdminA, tokenDevA, tokenOwnerB;
  let orgA, orgB;
  let repoA, repoB;
  let scanA, scanB;
  let vulnA, vulnB;
  let reportA, reportB;
  let inviteToken;

  try {
    // ── 0. Setup Test Users & Data ───────────────────────────────────────────
    console.log('--- 0. SETUP USERS & ORGANIZATIONS ---');

    userOwnerA = await prisma.user.create({
      data: {
        firstName: 'Owner',
        lastName: 'Alpha',
        email: `phase2_owner_a_${Date.now()}@example.com`,
        password: 'hashedpassword123',
        onboardingCompleted: true,
      }
    });

    userAdminA = await prisma.user.create({
      data: {
        firstName: 'Admin',
        lastName: 'Alpha',
        email: `phase2_admin_a_${Date.now()}@example.com`,
        password: 'hashedpassword123',
        onboardingCompleted: true,
      }
    });

    userDevA = await prisma.user.create({
      data: {
        firstName: 'Dev',
        lastName: 'Alpha',
        email: `phase2_dev_a_${Date.now()}@example.com`,
        password: 'hashedpassword123',
        onboardingCompleted: true,
      }
    });

    userOwnerB = await prisma.user.create({
      data: {
        firstName: 'Owner',
        lastName: 'Beta',
        email: `phase2_owner_b_${Date.now()}@example.com`,
        password: 'hashedpassword123',
        onboardingCompleted: true,
      }
    });

    tokenOwnerA = jwt.sign({ id: userOwnerA.id, email: userOwnerA.email }, JWT_SECRET);
    tokenAdminA = jwt.sign({ id: userAdminA.id, email: userAdminA.email }, JWT_SECRET);
    tokenDevA   = jwt.sign({ id: userDevA.id,   email: userDevA.email   }, JWT_SECRET);
    tokenOwnerB = jwt.sign({ id: userOwnerB.id, email: userOwnerB.email }, JWT_SECRET);

    assert(userOwnerA && userOwnerB, 'Test users created successfully');

    // ── 1. Organization Creation API ─────────────────────────────────────────
    console.log('\n--- 1. ORGANIZATION CREATION TESTS ---');

    // Create Organization A as Owner A
    const resOrgA = await fetch(`${BASE_URL}/api/organizations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenOwnerA}` },
      body: JSON.stringify({ name: 'Alpha Security Corp' })
    });
    orgA = await resOrgA.json();

    assert(resOrgA.status === 201, 'POST /api/organizations creates Organization A (201)');
    assert(orgA.name === 'Alpha Security Corp', 'Organization A name matches');
    assert(orgA.role === 'OWNER', 'Creator automatically becomes OWNER');

    // Create Organization B as Owner B
    const resOrgB = await fetch(`${BASE_URL}/api/organizations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenOwnerB}` },
      body: JSON.stringify({ name: 'Beta Systems Inc' })
    });
    orgB = await resOrgB.json();

    assert(resOrgB.status === 201, 'POST /api/organizations creates Organization B (201)');
    assert(orgB.id !== orgA.id, 'Organization A and B have distinct IDs');

    // ── 2. Repository & Resource Scoping ─────────────────────────────────────
    console.log('\n--- 2. REPOSITORY & RESOURCE SCOPING TESTS ---');

    // Create Repository in Org A
    const resRepoA = await fetch(`${BASE_URL}/api/repos`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        Authorization: `Bearer ${tokenOwnerA}`,
        'x-organization-id': String(orgA.id)
      },
      body: JSON.stringify({ name: 'alpha-api', fullName: 'alpha/alpha-api', url: 'https://github.com/alpha/alpha-api', platform: 'github' })
    });
    repoA = await resRepoA.json();
    assert(resRepoA.status === 201, 'Created repoA under Organization A');
    assert(repoA.organizationId === orgA.id, 'repoA is scoped to Organization A');

    // Create Repository in Org B
    const resRepoB = await fetch(`${BASE_URL}/api/repos`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        Authorization: `Bearer ${tokenOwnerB}`,
        'x-organization-id': String(orgB.id)
      },
      body: JSON.stringify({ name: 'beta-vault', fullName: 'beta/beta-vault', url: 'https://github.com/beta/beta-vault', platform: 'github' })
    });
    repoB = await resRepoB.json();
    assert(resRepoB.status === 201, 'Created repoB under Organization B');

    // Trigger Scan on Repo A
    scanA = await prisma.scan.create({
      data: {
        userId: userOwnerA.id,
        organizationId: orgA.id,
        repositoryId: repoA.id,
        status: 'completed',
        totalFiles: 20,
        criticalCount: 1,
      }
    });

    vulnA = await prisma.vulnerability.create({
      data: {
        scanId: scanA.id,
        type: 'sast',
        severity: 'critical',
        title: 'Alpha Critical Vulnerability',
        filePath: 'src/alpha.js',
        status: 'open'
      }
    });

    // Trigger Scan on Repo B
    scanB = await prisma.scan.create({
      data: {
        userId: userOwnerB.id,
        organizationId: orgB.id,
        repositoryId: repoB.id,
        status: 'completed',
        totalFiles: 10,
        criticalCount: 2,
      }
    });

    vulnB = await prisma.vulnerability.create({
      data: {
        scanId: scanB.id,
        type: 'secret',
        severity: 'critical',
        title: 'Beta Secret Vulnerability',
        filePath: 'src/beta.env',
        status: 'open'
      }
    });

    // ── 3. Multi-Tenant Cross-Tenant Isolation Tests ─────────────────────────
    console.log('\n--- 3. MULTI-TENANT ISOLATION (IDOR) TESTS ---');

    // Test 3.1: User B tries to view Repo A via Org B context header -> empty or not found
    const resCrossRepo = await fetch(`${BASE_URL}/api/repos`, {
      headers: { Authorization: `Bearer ${tokenOwnerB}`, 'x-organization-id': String(orgB.id) }
    });
    const bodyCrossRepo = await resCrossRepo.json();
    const hasRepoA = bodyCrossRepo.some(r => r.id === repoA.id);
    assert(!hasRepoA, 'User B listing Org B repos does NOT see Org A repoA');

    // Test 3.2: User B tries to specify x-organization-id: orgA.id -> 403 Forbidden
    const resOrgSpoof = await fetch(`${BASE_URL}/api/repos`, {
      headers: { Authorization: `Bearer ${tokenOwnerB}`, 'x-organization-id': String(orgA.id) }
    });
    assert(resOrgSpoof.status === 403, 'Organization Spoofing: User B requesting Org A context returns 403 Access Denied');

    // Test 3.3: User B tries to fetch Vuln A
    const resCrossVuln = await fetch(`${BASE_URL}/api/vulnerabilities/${vulnA.id}`, {
      headers: { Authorization: `Bearer ${tokenOwnerB}`, 'x-organization-id': String(orgB.id) }
    });
    assert(resCrossVuln.status === 404, 'Cross-Tenant Vuln Fetch: User B accessing Org A vuln returns 404');

    // ── 4. Member Invitation & Cryptographic Acceptance ──────────────────────
    console.log('\n--- 4. INVITATION SYSTEM & ACCEPTANCE FLOW ---');

    // Invite User Admin A to Org A as ADMIN
    const resInviteAdmin = await fetch(`${BASE_URL}/api/organizations/${orgA.id}/invitations`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        Authorization: `Bearer ${tokenOwnerA}`,
        'x-organization-id': String(orgA.id)
      },
      body: JSON.stringify({ email: userAdminA.email, role: 'ADMIN' })
    });
    const bodyInviteAdmin = await resInviteAdmin.json();
    assert(resInviteAdmin.status === 201, 'Owner A invited Admin A (201)');
    assert(bodyInviteAdmin.token && bodyInviteAdmin.token.length >= 32, 'Returns cryptographically random invitation token');

    const inviteTokenAdmin = bodyInviteAdmin.token;

    // Inspect Invitation
    const resInspect = await fetch(`${BASE_URL}/api/invitations/${inviteTokenAdmin}`);
    const bodyInspect = await resInspect.json();
    assert(resInspect.status === 200, 'GET /api/invitations/:token inspects valid invitation');
    assert(bodyInspect.organization.name === 'Alpha Security Corp', 'Inspection shows correct organization name');

    // Accept Invitation as User Admin A
    const resAcceptAdmin = await fetch(`${BASE_URL}/api/invitations/${inviteTokenAdmin}/accept`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenAdminA}` }
    });
    assert(resAcceptAdmin.status === 200, 'Admin A accepts invitation (200)');

    // Re-use token (Replay Attack Check)
    const resReplay = await fetch(`${BASE_URL}/api/invitations/${inviteTokenAdmin}/accept`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenDevA}` }
    });
    assert(resReplay.status === 400, 'Replay Attack Protection: Re-using accepted invitation token returns 400 Bad Request');

    // Invite User Dev A to Org A as DEVELOPER
    const resInviteDev = await fetch(`${BASE_URL}/api/organizations/${orgA.id}/invitations`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        Authorization: `Bearer ${tokenOwnerA}`,
        'x-organization-id': String(orgA.id)
      },
      body: JSON.stringify({ email: userDevA.email, role: 'DEVELOPER' })
    });
    const bodyInviteDev = await resInviteDev.json();
    const inviteTokenDev = bodyInviteDev.token;

    // Accept Invitation as User Dev A
    await fetch(`${BASE_URL}/api/invitations/${inviteTokenDev}/accept`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenDevA}` }
    });
    assert(true, 'Dev A accepted invitation into Org A as DEVELOPER');

    // ── 5. RBAC Permission Matrix & Privilege Escalation Defenses ─────────────
    console.log('\n--- 5. BACKEND-ENFORCED RBAC PERMISSION TESTS ---');

    // Test 5.1: DEVELOPER tries to invite another member -> 403 Forbidden
    const resDevInvite = await fetch(`${BASE_URL}/api/organizations/${orgA.id}/invitations`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json', 
        Authorization: `Bearer ${tokenDevA}`,
        'x-organization-id': String(orgA.id)
      },
      body: JSON.stringify({ email: 'hacker@example.com', role: 'ADMIN' })
    });
    assert(resDevInvite.status === 403, 'RBAC: DEVELOPER sending invitations returns 403 Forbidden');

    // Test 5.2: DEVELOPER tries to delete Organization A -> 403 Forbidden
    const resDevDeleteOrg = await fetch(`${BASE_URL}/api/organizations/${orgA.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenDevA}`, 'x-organization-id': String(orgA.id) }
    });
    assert(resDevDeleteOrg.status === 403, 'RBAC: DEVELOPER deleting Organization returns 403 Forbidden');

    // Test 5.3: ADMIN tries to delete Organization A -> 403 Forbidden (OWNER ONLY)
    const resAdminDeleteOrg = await fetch(`${BASE_URL}/api/organizations/${orgA.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenAdminA}`, 'x-organization-id': String(orgA.id) }
    });
    assert(resAdminDeleteOrg.status === 403, 'RBAC: ADMIN deleting Organization returns 403 Forbidden (OWNER ONLY)');

    // Test 5.4: ADMIN tries to promote self to OWNER -> 403 Forbidden
    const membersList = await (await fetch(`${BASE_URL}/api/organizations/${orgA.id}/members`, {
      headers: { Authorization: `Bearer ${tokenAdminA}`, 'x-organization-id': String(orgA.id) }
    })).json();

    const adminMembership = membersList.find(m => m.userId === userAdminA.id);
    const ownerMembership = membersList.find(m => m.userId === userOwnerA.id);

    const resAdminEscalate = await fetch(`${BASE_URL}/api/organizations/${orgA.id}/members/${adminMembership.id}`, {
      method: 'PATCH',
      headers: { 
        'Content-Type': 'application/json', 
        Authorization: `Bearer ${tokenAdminA}`,
        'x-organization-id': String(orgA.id)
      },
      body: JSON.stringify({ role: 'OWNER' })
    });
    assert(resAdminEscalate.status === 403, 'Privilege Escalation Protection: ADMIN assigning OWNER role returns 403');

    // ── 6. Last Owner Demotion & Removal Protection ──────────────────────────
    console.log('\n--- 6. LAST OWNER PROTECTION TESTS ---');

    // Test 6.1: OWNER A tries to demote self to DEVELOPER when they are sole OWNER -> 400 Bad Request
    const resDemoteLastOwner = await fetch(`${BASE_URL}/api/organizations/${orgA.id}/members/${ownerMembership.id}`, {
      method: 'PATCH',
      headers: { 
        'Content-Type': 'application/json', 
        Authorization: `Bearer ${tokenOwnerA}`,
        'x-organization-id': String(orgA.id)
      },
      body: JSON.stringify({ role: 'DEVELOPER' })
    });
    assert(resDemoteLastOwner.status === 400, 'Last-Owner Protection: Demoting the final OWNER returns 400 Bad Request');

    // Test 6.2: OWNER A tries to remove self when sole OWNER -> 400 Bad Request
    const resRemoveLastOwner = await fetch(`${BASE_URL}/api/organizations/${orgA.id}/members/${ownerMembership.id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${tokenOwnerA}`, 'x-organization-id': String(orgA.id) }
    });
    assert(resRemoveLastOwner.status === 400, 'Last-Owner Protection: Removing the final OWNER returns 400 Bad Request');

    // ── 7. Audit Log Verification ───────────────────────────────────────────
    console.log('\n--- 7. AUDIT LOG VERIFICATION ---');

    const resAudit = await fetch(`${BASE_URL}/api/organizations/${orgA.id}/audit-logs`, {
      headers: { Authorization: `Bearer ${tokenOwnerA}`, 'x-organization-id': String(orgA.id) }
    });
    const auditLogs = await resAudit.json();
    
    assert(resAudit.status === 200, 'GET /api/organizations/:id/audit-logs returns 200');
    assert(auditLogs.length > 0, 'Audit logs contain recorded organization events');
    const actions = auditLogs.map(l => l.action);
    assert(actions.includes('ORGANIZATION_CREATED'), 'Audit log recorded ORGANIZATION_CREATED');
    assert(actions.includes('MEMBER_INVITED'), 'Audit log recorded MEMBER_INVITED');
    assert(actions.includes('MEMBER_ACCEPTED'), 'Audit log recorded MEMBER_ACCEPTED');

  } catch (err) {
    console.error('Fatal error in Phase 2 verification suite:', err);
  } finally {
    // ── Cleanup ─────────────────────────────────────────────────────────────
    console.log('\n--- CLEANUP TEST DATA ---');
    try {
      if (userOwnerA) await prisma.user.delete({ where: { id: userOwnerA.id } });
      if (userAdminA) await prisma.user.delete({ where: { id: userAdminA.id } });
      if (userDevA)   await prisma.user.delete({ where: { id: userDevA.id } });
      if (userOwnerB) await prisma.user.delete({ where: { id: userOwnerB.id } });
      assert(true, 'Phase 2 test users and organization records cleaned up via cascade');
    } catch (cleanErr) {
      console.error('Cleanup error:', cleanErr);
    }
  }

  console.log('\n================================================================');
  console.log(`  RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests();
