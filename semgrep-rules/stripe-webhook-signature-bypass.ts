import Stripe from 'stripe';
function bad(body: string, sig: string | undefined, secret: string, stripe: Stripe) {
  // ruleid: driftguard.stripe.webhook-unverified-fallback
  if (!sig) {
    return JSON.parse(body) as Stripe.Event;
  }
  return stripe.webhooks.constructEvent(body, sig, secret);
}
function good(body: string, sig: string | undefined, secret: string, stripe: Stripe) {
  // ok: driftguard.stripe.webhook-unverified-fallback
  if (!sig) {
    throw new Error('missing signature');
  }
  return stripe.webhooks.constructEvent(body, sig, secret);
}
