const Stripe = require('stripe');

const stripeSecretKey = process.env.STRIPE_SECRET_KEY;

let stripe = null;

if (stripeSecretKey && stripeSecretKey !== 'sk_test_mock_secret_key') {
  stripe = new Stripe(stripeSecretKey, {
    apiVersion: '2023-10-16',
  });
} else {
  console.warn('[Stripe Utility] STRIPE_SECRET_KEY is missing or using test default. Live Stripe API integration in mock mode.');
}

/**
 * Returns active Stripe instance or mock throw if missing key
 */
function getStripeClient() {
  if (!stripe) {
    if (stripeSecretKey) {
      stripe = new Stripe(stripeSecretKey, { apiVersion: '2023-10-16' });
      return stripe;
    }
    throw new Error('STRIPE_SECRET_KEY is not configured in environment variables.');
  }
  return stripe;
}

module.exports = {
  stripe,
  getStripeClient
};
