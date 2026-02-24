/**
 * Subscription routes — paid tiers (Basic Subscriber, Super Fan).
 *
 * POST  /api/creator/subscriptions/settings  — creator sets pricing & toggle
 * GET   /api/creator/:id/subscriptions        — get a creator's tier info (public)
 * POST  /api/subscribe/:creatorId             — fan subscribes (tier 1 or 2)
 * POST  /api/upgrade/:creatorId               — fan upgrades to a higher tier
 */
import { Router, Response } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { requireAuth, AuthRequest } from '../middleware/auth';
import { HttpError } from '../middleware/errorHandler';
import { db } from '../models/store';
import { CreatorSettings, Entitlement, Subscription, SubscriptionTier } from '../types';
import {
  createStripeSubscription,
  ensureStripePrices,
} from '../services/stripeService';

const router = Router();

// ---------------------------------------------------------------------------
// Creator: configure subscription settings
// POST /api/creator/subscriptions/settings
// ---------------------------------------------------------------------------
const settingsSchema = z.object({
  subscriptionsEnabled: z.boolean().optional(),
  basicPriceCents: z.number().int().min(100).optional(), // min $1.00
  superFanPriceCents: z.number().int().min(100).optional(),
});

router.post(
  '/creator/subscriptions/settings',
  requireAuth,
  async (req: AuthRequest, res: Response) => {
    const creatorId = req.userId!;

    const parsed = settingsSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const existing: CreatorSettings = db.creatorSettings.get(creatorId) ?? {
      creatorId,
      subscriptionsEnabled: false,
      basicPriceCents: 499,
      superFanPriceCents: 999,
      stripeProductId: null,
      stripePriceIds: { basic: null, superFan: null },
    };

    const updated: CreatorSettings = { ...existing, ...parsed.data };
    db.creatorSettings.set(creatorId, updated);

    res.json({ settings: updated });
  }
);

// ---------------------------------------------------------------------------
// Public: get a creator's subscription tiers
// GET /api/creator/:id/subscriptions
// ---------------------------------------------------------------------------
router.get('/creator/:id/subscriptions', (req: AuthRequest, res: Response) => {
  const { id: creatorId } = req.params;

  if (!db.users.has(creatorId)) throw new HttpError(404, 'Creator not found');

  const settings = db.creatorSettings.get(creatorId);
  if (!settings?.subscriptionsEnabled) {
    res.json({
      subscriptionsEnabled: false,
      tiers: [],
    });
    return;
  }

  res.json({
    subscriptionsEnabled: true,
    tiers: [
      {
        tier: 1,
        name: 'Basic Subscriber',
        priceCents: settings.basicPriceCents,
        description: 'Support the creator · supporter-only posts · early access',
      },
      {
        tier: 2,
        name: 'Super Fan',
        priceCents: settings.superFanPriceCents,
        description:
          'Exclusive content · premium videos · behind-the-scenes · private feed',
      },
    ],
  });
});

// ---------------------------------------------------------------------------
// Fan: subscribe to a creator
// POST /api/subscribe/:creatorId
// ---------------------------------------------------------------------------
const subscribeSchema = z.object({
  tier: z.union([z.literal(1), z.literal(2)]),
  stripePaymentMethodId: z.string().optional(),
});

router.post(
  '/subscribe/:creatorId',
  requireAuth,
  async (req: AuthRequest, res: Response) => {
    const { creatorId } = req.params;
    const userId = req.userId!;

    if (!db.users.has(creatorId)) throw new HttpError(404, 'Creator not found');
    if (creatorId === userId) throw new HttpError(400, 'Cannot subscribe to yourself');

    const settings = db.creatorSettings.get(creatorId);
    if (!settings?.subscriptionsEnabled) {
      throw new HttpError(400, 'This creator has not enabled subscriptions');
    }

    const parsed = subscribeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const { tier, stripePaymentMethodId } = parsed.data;

    // Check for existing active subscription
    const existingEntitlement = db.entitlements.get(`${userId}:${creatorId}`);
    if (existingEntitlement?.active && existingEntitlement.tier >= tier) {
      res.status(409).json({
        error: 'Already subscribed at this tier or higher',
        currentTier: existingEntitlement.tier,
      });
      return;
    }

    let stripeSubscriptionId: string | null = null;

    if (stripePaymentMethodId && process.env.STRIPE_SECRET_KEY) {
      stripeSubscriptionId = await createStripeSubscription({
        userId,
        creatorId,
        tier,
        stripePaymentMethodId,
      });
      // Entitlement will be applied via the Stripe webhook
    } else {
      // No Stripe (dev/test mode): grant entitlement directly
      const expiresAt = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
      ).toISOString();
      const entitlement: Entitlement = {
        userId,
        creatorId,
        tier: tier as SubscriptionTier,
        active: true,
        expiresAt,
      };
      db.entitlements.set(`${userId}:${creatorId}`, entitlement);
    }

    const now = new Date().toISOString();
    const id = uuidv4();
    const subscription: Subscription = {
      id,
      userId,
      creatorId,
      tier: tier as SubscriptionTier,
      active: true,
      expiresAt: stripeSubscriptionId
        ? null // managed by webhook
        : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      stripeSubscriptionId,
      createdAt: now,
    };
    db.subscriptions.set(id, subscription);

    res.status(201).json({ subscription });
  }
);

// ---------------------------------------------------------------------------
// Fan: upgrade subscription tier
// POST /api/upgrade/:creatorId
// ---------------------------------------------------------------------------
const upgradeSchema = z.object({
  tier: z.union([z.literal(1), z.literal(2)]),
  stripePaymentMethodId: z.string().optional(),
});

router.post(
  '/upgrade/:creatorId',
  requireAuth,
  async (req: AuthRequest, res: Response) => {
    const { creatorId } = req.params;
    const userId = req.userId!;

    if (!db.users.has(creatorId)) throw new HttpError(404, 'Creator not found');

    const parsed = upgradeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const { tier, stripePaymentMethodId } = parsed.data;

    const existingEntitlement = db.entitlements.get(`${userId}:${creatorId}`);
    if (!existingEntitlement?.active) {
      throw new HttpError(400, 'No active subscription to upgrade');
    }
    if (existingEntitlement.tier >= tier) {
      throw new HttpError(400, 'Already at this tier or higher');
    }

    const settings = db.creatorSettings.get(creatorId);
    if (!settings?.subscriptionsEnabled) {
      throw new HttpError(400, 'This creator has not enabled subscriptions');
    }

    let stripeSubscriptionId: string | null = null;

    if (stripePaymentMethodId && process.env.STRIPE_SECRET_KEY) {
      // Cancel old Stripe subscription and create new one at higher tier
      const existingSub = [...db.subscriptions.values()].find(
        (s) => s.userId === userId && s.creatorId === creatorId && s.active
      );
      if (existingSub?.stripeSubscriptionId) {
        const { default: Stripe } = await import('stripe');
        const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
          apiVersion: '2026-01-28.clover',
        });
        await stripe.subscriptions.cancel(existingSub.stripeSubscriptionId);
      }

      stripeSubscriptionId = await createStripeSubscription({
        userId,
        creatorId,
        tier,
        stripePaymentMethodId,
      });
    } else {
      // Dev/test mode: update entitlement directly
      const expiresAt = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
      ).toISOString();
      db.entitlements.set(`${userId}:${creatorId}`, {
        ...existingEntitlement,
        tier: tier as SubscriptionTier,
        expiresAt,
      });
    }

    const now = new Date().toISOString();
    const id = uuidv4();
    const subscription: Subscription = {
      id,
      userId,
      creatorId,
      tier: tier as SubscriptionTier,
      active: true,
      expiresAt: stripeSubscriptionId
        ? null
        : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      stripeSubscriptionId,
      createdAt: now,
    };
    db.subscriptions.set(id, subscription);

    res.json({ subscription });
  }
);

// ---------------------------------------------------------------------------
// Re-export Stripe webhook as a named export for mounting in index.ts
// ---------------------------------------------------------------------------
export { router as subscriptionsRouter };
export { ensureStripePrices };
export default router;
