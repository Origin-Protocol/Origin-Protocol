import { Response, NextFunction } from 'express';
import { AuthRequest } from './auth';
import { db } from '../models/store';
import { SubscriptionTier } from '../types';

/**
 * Factory that returns a middleware which verifies the calling user holds an
 * active entitlement of at least `requiredTier` for a specific creator.
 *
 * The `creatorId` is read from `req.params.creatorId` by default; pass an
 * explicit value to override (e.g. when it lives in a different param).
 *
 * Usage:
 *   router.get('/exclusive', requireAuth, requireEntitlement(1), handler)
 */
export function requireEntitlement(
  requiredTier: SubscriptionTier,
  creatorParamKey = 'creatorId'
) {
  return (req: AuthRequest, res: Response, next: NextFunction): void => {
    const userId = req.userId!;
    const creatorId = req.params[creatorParamKey];

    if (!creatorId) {
      res.status(400).json({ error: 'creatorId param is missing' });
      return;
    }

    const key = `${userId}:${creatorId}`;
    const entitlement = db.entitlements.get(key);

    if (!entitlement || !entitlement.active) {
      res.status(403).json({ error: 'Active subscription required' });
      return;
    }

    // Check expiry
    if (entitlement.expiresAt && new Date(entitlement.expiresAt) < new Date()) {
      // Mark as inactive lazily
      db.entitlements.set(key, { ...entitlement, active: false });
      res.status(403).json({ error: 'Subscription has expired' });
      return;
    }

    if (entitlement.tier < requiredTier) {
      res.status(403).json({ error: `Tier ${requiredTier} or higher required` });
      return;
    }

    next();
  };
}
