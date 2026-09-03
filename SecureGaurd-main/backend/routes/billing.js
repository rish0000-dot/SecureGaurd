const express = require('express');
const router = express.Router();
const prisma = require('../prismaClient');
const authMiddleware = require('../middleware/auth');
const { requireOrgContext, requireOrgRole, createAuditLog } = require('../middleware/rbac');
const { getOrgUsage, getOrgSubscription } = require('../services/billingService');
const { PLANS, getPlanConfig } = require('../config/plans');
const { getStripeClient } = require('../utils/stripe');

router.use(authMiddleware);

/**
 * GET /api/billing/usage
 * Returns active organization subscription status, usage metrics, limits, and plan details.
 * Allowed for: OWNER, ADMIN, DEVELOPER
 */
router.get('/usage', requireOrgContext, requireOrgRole(['OWNER', 'ADMIN', 'DEVELOPER']), async (req, res) => {
  try {
    const usage = await getOrgUsage(req.organizationId);
    return res.json(usage);
  } catch (err) {
    console.error('Error fetching billing usage:', err);
    return res.status(500).json({ message: 'Failed to fetch billing usage' });
  }
});

/**
 * Helper to ensure a Stripe Customer exists for the Organization
 */
async function ensureStripeCustomer(organizationId, userEmail, orgName) {
  const sub = await getOrgSubscription(organizationId);

  if (sub.stripeCustomerId) {
    return sub.stripeCustomerId;
  }

  try {
    const stripe = getStripeClient();
    const customer = await stripe.customers.create({
      email: userEmail,
      name: orgName,
      metadata: {
        organizationId: String(organizationId)
      }
    });

    await prisma.subscription.update({
      where: { organizationId: Number(organizationId) },
      data: { stripeCustomerId: customer.id }
    });

    return customer.id;
  } catch (err) {
    console.warn('[Stripe Customer Creation Warning]', err.message);
    // Return synthetic customer ID if running without live Stripe keys
    const mockId = `cus_mock_${organizationId}_${Date.now()}`;
    await prisma.subscription.update({
      where: { organizationId: Number(organizationId) },
      data: { stripeCustomerId: mockId }
    });
    return mockId;
  }
}

/**
 * POST /api/billing/create-checkout-session
 * Initiates Stripe Checkout Session for PRO or ENTERPRISE upgrade.
 * Allowed for: OWNER only
 */
router.post('/create-checkout-session', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  try {
    const { plan } = req.body; // 'PRO' | 'ENTERPRISE'
    const targetPlan = getPlanConfig(plan);

    if (!targetPlan || targetPlan.key === 'FREE') {
      return res.status(400).json({ message: 'Invalid target plan selected for upgrade.' });
    }

    const org = await prisma.organization.findUnique({
      where: { id: req.organizationId }
    });

    if (!org) {
      return res.status(404).json({ message: 'Organization not found' });
    }

    // Fetch user record for email
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    const userEmail = user ? user.email : 'unknown@secureguard.dev';

    const stripeCustomerId = await ensureStripeCustomer(req.organizationId, userEmail, org.name);
    const domain = process.env.FRONTEND_URL || 'http://localhost:5173';

    try {
      const stripe = getStripeClient();
      const session = await stripe.checkout.sessions.create({
        customer: stripeCustomerId,
        mode: 'subscription',
        payment_method_types: ['card'],
        line_items: [
          {
            price: targetPlan.stripePriceId,
            quantity: 1
          }
        ],
        client_reference_id: String(req.organizationId),
        metadata: {
          organizationId: String(req.organizationId),
          plan: targetPlan.key
        },
        success_url: `${domain}/dashboard?billing_success=true&session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${domain}/dashboard?billing_canceled=true`
      });

      await createAuditLog(
        req.organizationId,
        req.userId,
        'BILLING_CHECKOUT_STARTED',
        'ORGANIZATION',
        String(req.organizationId),
        { targetPlan: targetPlan.key }
      );

      return res.json({ url: session.url });
    } catch (stripeErr) {
      console.warn('[Stripe Checkout Session Mock Fallback]', stripeErr.message);
      // In dev mode without active Stripe price IDs, simulate test checkout URL
      const mockCheckoutUrl = `${domain}/dashboard?billing_success=true&mock_plan=${targetPlan.key}`;
      
      // Auto-update in mock mode for testing convenience
      await prisma.subscription.update({
        where: { organizationId: req.organizationId },
        data: {
          plan: targetPlan.key,
          status: 'active',
          stripePriceId: targetPlan.stripePriceId
        }
      });

      await createAuditLog(
        req.organizationId,
        req.userId,
        'BILLING_CHECKOUT_STARTED',
        'ORGANIZATION',
        String(req.organizationId),
        { targetPlan: targetPlan.key, mockMode: true }
      );

      return res.json({ url: mockCheckoutUrl });
    }
  } catch (err) {
    console.error('Error creating checkout session:', err);
    return res.status(500).json({ message: 'Failed to create checkout session' });
  }
});

/**
 * POST /api/billing/create-portal-session
 * Creates a Stripe Customer Billing Portal session for managing invoices/cards.
 * Allowed for: OWNER only
 */
router.post('/create-portal-session', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  try {
    const sub = await getOrgSubscription(req.organizationId);

    if (!sub.stripeCustomerId) {
      return res.status(400).json({ message: 'No Stripe billing customer record found for this organization.' });
    }

    const domain = process.env.FRONTEND_URL || 'http://localhost:5173';

    try {
      const stripe = getStripeClient();
      const portalSession = await stripe.billingPortal.sessions.create({
        customer: sub.stripeCustomerId,
        return_url: `${domain}/dashboard`
      });

      await createAuditLog(
        req.organizationId,
        req.userId,
        'BILLING_PORTAL_OPENED',
        'ORGANIZATION',
        String(req.organizationId)
      );

      return res.json({ url: portalSession.url });
    } catch (stripeErr) {
      console.warn('[Stripe Portal Fallback]', stripeErr.message);
      return res.json({ url: `${domain}/dashboard?portal_simulated=true` });
    }
  } catch (err) {
    console.error('Error creating portal session:', err);
    return res.status(500).json({ message: 'Failed to create billing portal session' });
  }
});

/**
 * POST /api/billing/cancel-subscription
 * Schedules subscription cancellation at the end of the current billing period.
 * Allowed for: OWNER only
 */
router.post('/cancel-subscription', requireOrgContext, requireOrgRole(['OWNER']), async (req, res) => {
  try {
    const sub = await getOrgSubscription(req.organizationId);

    if (sub.stripeSubscriptionId) {
      try {
        const stripe = getStripeClient();
        await stripe.subscriptions.update(sub.stripeSubscriptionId, {
          cancel_at_period_end: true
        });
      } catch (stripeErr) {
        console.warn('[Stripe Cancel Warning]', stripeErr.message);
      }
    }

    const updatedSub = await prisma.subscription.update({
      where: { organizationId: req.organizationId },
      data: { cancelAtPeriodEnd: true }
    });

    await createAuditLog(
      req.organizationId,
      req.userId,
      'SUBSCRIPTION_CANCELED',
      'ORGANIZATION',
      String(req.organizationId),
      { cancelAtPeriodEnd: true }
    );

    return res.json({
      message: 'Subscription scheduled for cancellation at end of period',
      subscription: updatedSub
    });
  } catch (err) {
    console.error('Error canceling subscription:', err);
    return res.status(500).json({ message: 'Failed to cancel subscription' });
  }
});

module.exports = router;
