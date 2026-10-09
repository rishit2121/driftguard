import type Stripe from 'stripe';
import { PRIMARY_PRICE_ID } from './plans.ts';

// Added by DriftGuard for upstream change {{change_id}}
// Source: {{source_url}}
// Stripe API 2025-03-31.basil moved current_period_start/current_period_end from the Subscription onto each
// SubscriptionItem (items may have different intervals). Resolve the period from the item that carries the
// plan price. Payloads from endpoints still pinned to older versions keep the subscription-level fields.
export interface BillingPeriod {
  start: number;
  end: number;
}

export function billingPeriod(subscription: Stripe.Subscription, priceId: string = PRIMARY_PRICE_ID): BillingPeriod {
  const pinned = subscription as unknown as { current_period_start?: number; current_period_end?: number };
  if (typeof pinned.current_period_start === 'number' && typeof pinned.current_period_end === 'number') {
    return { start: pinned.current_period_start, end: pinned.current_period_end };
  }
  const item = subscription.items.data.find((candidate) => candidate.price?.id === priceId);
  if (!item) {
    throw new Error(`subscription ${subscription.id} has no item for price ${priceId}`);
  }
  return { start: item.current_period_start, end: item.current_period_end };
}
