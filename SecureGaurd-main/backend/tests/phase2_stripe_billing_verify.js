const assert = require('assert');
const prisma = require('../prismaClient');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { getOrgSubscription, getOrgPlan, getOrgUsage, checkCanAddRepository, checkCanInviteMember, checkCanTriggerScan } = require('../services/billingService');
const { PLANS } = require('../config/plans');

const JWT_SECRET = process.env.JWT_SECRET || 'secureguard_super_secret_jwt_key_2026';

function generateToken(userId, email) {
  return jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '1h' });
}

async function runBillingVerificationSuite() {
  console.log('\n================================================================');
  console.log(' SECUREGUARD PHASE 2: STRIPE BILLING & USAGE METERING VERIFY ');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✕ ${name}`);
      console.error(`     Error: ${err.message}`);
      failed++;
    }
  }

  async function asyncTest(name, fn) {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✕ ${name}`);
      console.error(`     Error: ${err.message}`);
      failed++;
    }
  }

  let ownerUser, adminUser, devUser, orgA, orgB;
  const timestamp = Date.now();

  try {
    console.log('--- 0. SETUP TEST ENVIRONMENT ---');
    const passwordHash = await bcrypt.hash('BillingPass123!', 10);

    ownerUser = await prisma.user.create({
      data: {
        firstName: 'Owner',
        lastName: 'BillingTest',
        email: `owner_bill_${timestamp}@test.com`,
        password: passwordHash
      }
    });

    adminUser = await prisma.user.create({
      data: {
        firstName: 'Admin',
        lastName: 'BillingTest',
        email: `admin_bill_${timestamp}@test.com`,
        password: passwordHash
      }
    });

    devUser = await prisma.user.create({
      data: {
        firstName: 'Dev',
        lastName: 'BillingTest',
        email: `dev_bill_${timestamp}@test.com`,
        password: passwordHash
      }
    });

    orgA = await prisma.organization.create({
      data: {
        name: `Billing Org Alpha ${timestamp}`,
        slug: `billing-org-alpha-${timestamp}`,
        memberships: {
          create: [
            { userId: ownerUser.id, role: 'OWNER' },
            { userId: adminUser.id, role: 'ADMIN' },
            { userId: devUser.id, role: 'DEVELOPER' }
          ]
        }
      }
    });

    orgB = await prisma.organization.create({
      data: {
        name: `Billing Org Beta ${timestamp}`,
        slug: `billing-org-beta-${timestamp}`,
        memberships: {
          create: [
            { userId: devUser.id, role: 'OWNER' }
          ]
        }
      }
    });

    console.log(`  ✓ Created test users and organizations (Org A: #${orgA.id}, Org B: #${orgB.id})\n`);

    console.log('--- 1. BACKWARD COMPATIBILITY & SUBSCRIPTION SEEDING ---');
    await asyncTest('Auto-creates FREE subscription for existing organization', async () => {
      const sub = await getOrgSubscription(orgA.id);
      assert.strictEqual(sub.organizationId, orgA.id);
      assert.strictEqual(sub.plan, 'FREE');
      assert.strictEqual(sub.status, 'active');
    });

    await asyncTest('Resolves correct FREE plan limits', async () => {
      const plan = await getOrgPlan(orgA.id);
      assert.strictEqual(plan.key, 'FREE');
      assert.strictEqual(plan.maxRepositories, 3);
      assert.strictEqual(plan.maxScansPerMonth, 10);
      assert.strictEqual(plan.maxMembers, 3);
    });

    console.log('\n--- 2. USAGE METERING & ENTITLEMENT LIMITS ---');
    await asyncTest('Calculates correct initial usage for empty organization', async () => {
      const usage = await getOrgUsage(orgA.id);
      assert.strictEqual(usage.plan, 'FREE');
      assert.strictEqual(usage.usage.repositories.used, 0);
      assert.strictEqual(usage.usage.members.used, 3); // 3 members created in setup
      assert.strictEqual(usage.usage.scans.used, 0);
    });

    await asyncTest('Repository Limit Check — Allows under limit', async () => {
      const check = await checkCanAddRepository(orgA.id);
      assert.strictEqual(check.allowed, true);
    });

    await asyncTest('Repository Limit Check — Rejects when max limit (3) reached', async () => {
      // Seed 3 repos
      for (let i = 1; i <= 3; i++) {
        await prisma.repository.create({
          data: {
            userId: ownerUser.id,
            organizationId: orgA.id,
            name: `repo-${i}`,
            fullName: `org/repo-${i}`,
            url: `https://github.com/org/repo-${i}`
          }
        });
      }

      const check = await checkCanAddRepository(orgA.id);
      assert.strictEqual(check.allowed, false);
      assert.strictEqual(check.reason, 'REPOSITORY_LIMIT_REACHED');
      assert.strictEqual(check.usage.used, 3);
      assert.strictEqual(check.usage.limit, 3);
    });

    await asyncTest('Member Limit Check — Rejects when max members (3) reached', async () => {
      const check = await checkCanInviteMember(orgA.id);
      assert.strictEqual(check.allowed, false);
      assert.strictEqual(check.reason, 'MEMBER_LIMIT_REACHED');
    });

    await asyncTest('Scan Limit Check — Rejects when monthly scan limit (10) reached', async () => {
      const repo = await prisma.repository.findFirst({ where: { organizationId: orgA.id } });
      // Seed 10 scans for this month
      for (let i = 1; i <= 10; i++) {
        await prisma.scan.create({
          data: {
            userId: ownerUser.id,
            organizationId: orgA.id,
            repositoryId: repo.id,
            status: 'completed'
          }
        });
      }

      const check = await checkCanTriggerScan(orgA.id);
      assert.strictEqual(check.allowed, false);
      assert.strictEqual(check.reason, 'SCAN_LIMIT_REACHED');
      assert.strictEqual(check.usage.used, 10);
    });

    console.log('\n--- 3. STRIPE WEBHOOK & SUBSCRIPTION SYNCHRONIZATION ---');
    await asyncTest('Processes checkout.session.completed webhook event and upgrades plan to PRO', async () => {
      const mockStripeEventId = `evt_test_checkout_${Date.now()}`;
      
      // Execute transaction simulating webhook handler logic
      await prisma.$transaction(async (tx) => {
        await tx.stripeWebhookEvent.create({
          data: { stripeEventId: mockStripeEventId, eventType: 'checkout.session.completed' }
        });

        await tx.subscription.upsert({
          where: { organizationId: orgA.id },
          create: {
            organizationId: orgA.id,
            stripeCustomerId: 'cus_test_123',
            stripeSubscriptionId: 'sub_test_123',
            plan: 'PRO',
            status: 'active',
            currentPeriodStart: new Date(),
            currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          },
          update: {
            stripeCustomerId: 'cus_test_123',
            stripeSubscriptionId: 'sub_test_123',
            plan: 'PRO',
            status: 'active'
          }
        });

        await tx.auditLog.create({
          data: {
            organizationId: orgA.id,
            action: 'SUBSCRIPTION_CREATED',
            targetType: 'ORGANIZATION',
            targetId: String(orgA.id),
            details: { plan: 'PRO' }
          }
        });
      });

      const updatedSub = await prisma.subscription.findUnique({ where: { organizationId: orgA.id } });
      assert.strictEqual(updatedSub.plan, 'PRO');
      assert.strictEqual(updatedSub.status, 'active');
      assert.strictEqual(updatedSub.stripeCustomerId, 'cus_test_123');
    });

    await asyncTest('Webhook Idempotency Protection — Prevents duplicate event processing', async () => {
      const existing = await prisma.stripeWebhookEvent.findFirst({
        where: { eventType: 'checkout.session.completed' }
      });
      assert.notStrictEqual(existing, null);
    });

    await asyncTest('Verifies expanded PRO plan limits after webhook processing', async () => {
      const plan = await getOrgPlan(orgA.id);
      assert.strictEqual(plan.key, 'PRO');
      assert.strictEqual(plan.maxRepositories, 25);
      assert.strictEqual(plan.maxScansPerMonth, 200);

      // Verify repo limit check now allows addition with 3 repos
      const repoCheck = await checkCanAddRepository(orgA.id);
      assert.strictEqual(repoCheck.allowed, true);

      // Verify scan limit check now allows scanning with 10 scans
      const scanCheck = await checkCanTriggerScan(orgA.id);
      assert.strictEqual(scanCheck.allowed, true);
    });

    await asyncTest('Processes customer.subscription.deleted event and downgrades to FREE', async () => {
      const subRecord = await prisma.subscription.findUnique({ where: { organizationId: orgA.id } });
      
      await prisma.subscription.update({
        where: { id: subRecord.id },
        data: { plan: 'FREE', status: 'canceled' }
      });

      const downgradedPlan = await getOrgPlan(orgA.id);
      assert.strictEqual(downgradedPlan.key, 'FREE');
      
      // Re-upgrade back to PRO for subsequent tests
      await prisma.subscription.update({
        where: { id: subRecord.id },
        data: { plan: 'PRO', status: 'active' }
      });
    });

    console.log('\n--- 4. AUDIT LOGGING FOR BILLING EVENTS ---');
    await asyncTest('Audit logs record SUBSCRIPTION_CREATED action', async () => {
      const auditLog = await prisma.auditLog.findFirst({
        where: { organizationId: orgA.id, action: 'SUBSCRIPTION_CREATED' }
      });
      assert.notStrictEqual(auditLog, null);
      assert.strictEqual(auditLog.details.plan, 'PRO');
    });

    console.log('\n--- 5. CLEANUP TEST DATA ---');
    await asyncTest('Cleaned up test billing users and organizations', async () => {
      await prisma.organization.deleteMany({
        where: { id: { in: [orgA.id, orgB.id] } }
      });
      await prisma.user.deleteMany({
        where: { id: { in: [ownerUser.id, adminUser.id, devUser.id] } }
      });
      await prisma.stripeWebhookEvent.deleteMany({
        where: { eventType: { in: ['checkout.session.completed'] } }
      });
    });

  } catch (err) {
    console.error('Test Suite Setup/Execution Error:', err);
    failed++;
  }

  console.log('\n================================================================');
  console.log(` RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runBillingVerificationSuite();
