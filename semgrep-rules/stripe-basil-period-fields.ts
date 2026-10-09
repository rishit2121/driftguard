import type Stripe from 'stripe';

function a(sub: Stripe.Subscription) {
  // ruleid: driftguard.stripe.subscription-period-fields-removed-basil
  return sub.current_period_end;
}
function b(sub: Stripe.Subscription) {
  // ruleid: driftguard.stripe.subscription-period-fields-removed-basil
  const { current_period_start: s } = sub;
  return s;
}
function c(event: Stripe.Event) {
  const sub = event.data.object as Stripe.Subscription;
  // ruleid: driftguard.stripe.subscription-period-fields-removed-basil
  return sub.current_period_end;
}
interface Report { current_period_end: number }
function d(r: Report) {
  // ok: driftguard.stripe.subscription-period-fields-removed-basil
  return r.current_period_end;
}
function e(sub: Stripe.Subscription, priceId: string) {
  // ok: driftguard.stripe.subscription-period-fields-removed-basil
  return sub.items.data.find((i) => i.price.id === priceId)?.current_period_end;
}
