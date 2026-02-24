/**
 * Stripe integration for the Follow / Subscribe system.
 *
 * In production, set the STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET
 * environment variables.  When the key is absent the service runs in
 * "no-op" mode so that the rest of the server can still start without
 * real Stripe credentials.
 */
import Stripe from 'stripe';
import { Request, Response } from 'express';
import { db } from '../models/store';
import { Entitlement, SubscriptionTier } from '../types';

// Initialise Stripe only when the secret key is available
const stripeSecretKey = process.env.STRIPE_SECRET_KEY ?? '';
const stripe: Stripe | null = stripeSecretKey
  ? new Stripe(stripeSecretKey, { apiVersion: '2026-01-28.clover' })
  : null;

const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET ?? '';

// --------------------------------------------------------------------------
// Product / Price helpers
// --------------------------------------------------------------------------

/**
 * Ensure a Stripe Product exists for the given creator and return its ID.
 * Creates it if it does not yet exist.
 */
export async function ensureStripeProduct(creatorId: string): Promise<string> {
  if (!stripe) throw new Error('Stripe is not configured');

  const settings = db.creatorSettings.get(creatorId);
  if (settings?.stripeProductId) return settings.stripeProductId;

  const product = await stripe.products.create({
    name: `Creator ${creatorId} — subscriptions`,
    metadata: { creatorId },
  });

  const updated = {
    ...(settings ?? {
      creatorId,
      subscriptionsEnabled: true,
      basicPriceCents: 499,
      superFanPriceCents: 999,
      stripePriceIds: { basic: null, superFan: null },
    }),
    stripeProductId: product.id,
  };
  db.creatorSettings.set(creatorId, updated);

  return product.id;
}

/**
 * Ensure Stripe Price objects exist for both tiers and return their IDs.
 */
export async function ensureStripePrices(
  creatorId: string
): Promise<{ basic: string; superFan: string }> {
  if (!stripe) throw new Error('Stripe is not configured');

  const productId = await ensureStripeProduct(creatorId);
  const settings = db.creatorSettings.get(creatorId)!;

  const basicPriceId =
    settings.stripePriceIds.basic ??
    (
      await stripe.prices.create({
        product: productId,
        unit_amount: settings.basicPriceCents,
        currency: 'usd',
        recurring: { interval: 'month' },
        metadata: { creatorId, tier: '1' },
      })
    ).id;

  const superFanPriceId =
    settings.stripePriceIds.superFan ??
    (
      await stripe.prices.create({
        product: productId,
        unit_amount: settings.superFanPriceCents,
        currency: 'usd',
        recurring: { interval: 'month' },
        metadata: { creatorId, tier: '2' },
      })
    ).id;

  db.creatorSettings.set(creatorId, {
    ...settings,
    stripePriceIds: { basic: basicPriceId, superFan: superFanPriceId },
  });

  return { basic: basicPriceId, superFan: superFanPriceId };
}

/**
 * Create (or upgrade) a Stripe subscription for a user/creator/tier.
 * Returns the Stripe subscription ID.
 */
export async function createStripeSubscription(params: {
  userId: string;
  creatorId: string;
  tier: 1 | 2;
  stripePaymentMethodId: string;
}): Promise<string> {
  if (!stripe) throw new Error('Stripe is not configured');

  const { userId, creatorId, tier, stripePaymentMethodId } = params;
  const prices = await ensureStripePrices(creatorId);
  const priceId = tier === 1 ? prices.basic : prices.superFan;

  // Re-use or create a Stripe Customer for this user
  const user = db.users.get(userId);
  if (!user) throw new Error('User not found');

  const customers = await stripe.customers.list({ email: user.email, limit: 1 });
  const customer =
    customers.data[0] ??
    (await stripe.customers.create({
      email: user.email,
      name: user.displayName,
      metadata: { userId },
    }));

  // Attach the payment method
  await stripe.paymentMethods.attach(stripePaymentMethodId, {
    customer: customer.id,
  });
  await stripe.customers.update(customer.id, {
    invoice_settings: { default_payment_method: stripePaymentMethodId },
  });

  const subscription = await stripe.subscriptions.create({
    customer: customer.id,
    items: [{ price: priceId }],
    metadata: { userId, creatorId, tier: String(tier) },
    expand: ['latest_invoice.payment_intent'],
  });

  return subscription.id;
}

// --------------------------------------------------------------------------
// Webhook handler
// --------------------------------------------------------------------------

/**
 * Express handler for POST /api/stripe/webhook.
 *
 * Must be mounted BEFORE express.json() middleware because Stripe requires
 * the raw body for signature verification.  In index.ts the route is
 * registered with express.raw({ type: 'application/json' }).
 */
export async function stripeWebhookHandler(
  req: Request,
  res: Response
): Promise<void> {
  if (!stripe) {
    res.status(400).json({ error: 'Stripe is not configured' });
    return;
  }

  const sig = req.headers['stripe-signature'] as string;
  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(req.body as Buffer, sig, webhookSecret);
  } catch (err) {
    res.status(400).json({ error: `Webhook signature verification failed: ${(err as Error).message}` });
    return;
  }

  switch (event.type) {
    case 'customer.subscription.created':
    case 'customer.subscription.updated': {
      const sub = event.data.object as Stripe.Subscription;
      applySubscriptionEvent(sub, /* active */ sub.status === 'active');
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object as Stripe.Subscription;
      applySubscriptionEvent(sub, /* active */ false);
      break;
    }
    case 'invoice.payment_failed': {
      const invoice = event.data.object as Stripe.Invoice;
      const subRef = invoice.parent?.subscription_details?.subscription;
      const subId = typeof subRef === 'string' ? subRef : subRef?.id;
      if (subId) {
        const sub = await stripe.subscriptions.retrieve(subId);
        applySubscriptionEvent(sub, /* active */ false);
      }
      break;
    }
    default:
      // Ignore unhandled events
      break;
  }

  res.json({ received: true });
}

/** Apply a Stripe subscription event to the in-memory store. */
function applySubscriptionEvent(sub: Stripe.Subscription, active: boolean): void {
  const { userId, creatorId, tier: tierStr } = sub.metadata as {
    userId: string;
    creatorId: string;
    tier: string;
  };

  if (!userId || !creatorId || !tierStr) return;

  const tier = parseInt(tierStr, 10) as SubscriptionTier;
  // Use cancel_at as the expiry if set, otherwise null (active until cancelled)
  const expiresAt = sub.cancel_at
    ? new Date(sub.cancel_at * 1000).toISOString()
    : null;

  const entitlement: Entitlement = {
    userId,
    creatorId,
    tier,
    active,
    expiresAt,
  };

  db.entitlements.set(`${userId}:${creatorId}`, entitlement);

  // Mirror into the subscriptions map (upsert by stripeSubscriptionId)
  for (const [key, existing] of db.subscriptions.entries()) {
    if (existing.stripeSubscriptionId === sub.id) {
      db.subscriptions.set(key, { ...existing, tier, active, expiresAt });
      return;
    }
  }
}
