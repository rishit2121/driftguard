// Added by DriftGuard for upstream change {{change_id}}
// Source: {{source_url}}
// Replays the recorded pre-version (2024-12-18.acacia) and post-version (2025-03-31.basil) fixtures through the
// production code paths. The post-version cases FAIL on code that reads subscription-level billing periods.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import Stripe from 'stripe';
import { getRenewalDate, summarizeRenewal } from '../../src/stripe/subscription.ts';
import { describeUpcomingInvoice } from '../../src/stripe/invoice-preview.ts';
import { handleStripeWebhook, resetProcessedEvents } from '../../src/stripe/webhook-handler.ts';

const read = (dir: string, name: string) => {
  const { _provenance, ...body } = JSON.parse(readFileSync(new URL(`../../../../fixtures/${dir}/${name}`, import.meta.url), 'utf8'));
  return body;
};
const OLD = read('api', 'stripe-old-subscription.json');
const NEW = read('api', 'stripe-new-subscription.json');
const SECRET = 'whsec_driftguard_demo_only';
const stripe = new Stripe('sk_test_placeholder');
const deliver = (name: string) => {
  resetProcessedEvents();
  const payload = JSON.stringify(read('webhook', name));
  return handleStripeWebhook(payload, stripe.webhooks.generateTestHeaderString({ payload, secret: SECRET }), SECRET, stripe);
};

test('[pre 2024-12-18.acacia] renewal date', () => {
  assert.equal(getRenewalDate(OLD).toISOString(), '2026-01-01T00:00:00.000Z');
});
test('[post 2025-03-31.basil] renewal date comes from the primary plan item, not items.data[0]', () => {
  assert.equal(getRenewalDate(NEW).toISOString(), '2026-07-01T00:00:00.000Z');
});
test('[post 2025-03-31.basil] renewal summary period start', () => {
  assert.equal(summarizeRenewal(NEW, new Date('2026-06-01T00:00:00Z')).periodStart, '2025-07-01T00:00:00.000Z');
});
test('[pre 2024-12-18.acacia] upcoming invoice description', () => {
  assert.equal(describeUpcomingInvoice(OLD), 'Next invoice for sub_demo_old_0001 is due 2026-01-01');
});
test('[post 2025-03-31.basil] upcoming invoice description', () => {
  assert.equal(describeUpcomingInvoice(NEW), 'Next invoice for sub_demo_new_0002 is due 2026-07-01');
});
test('[pre 2024-12-18.acacia] webhook replay grants access until period end', () => {
  assert.equal(deliver('stripe-old-event.json')?.accessUntil, '2026-01-01T00:00:00.000Z');
});
test('[post 2025-03-31.basil] webhook replay grants access until plan period end', () => {
  assert.equal(deliver('stripe-new-event.json')?.accessUntil, '2026-07-01T00:00:00.000Z');
});
