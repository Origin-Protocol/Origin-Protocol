/**
 * Exclusive content routes.
 *
 * POST /api/content                          — creator uploads exclusive content metadata
 * GET  /api/content/:contentId               — fan accesses exclusive content (entitlement check)
 * GET  /api/content/creator/:creatorId       — list exclusive content for a creator
 */
import { Router, Response, Request } from 'express';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { requireAuth, AuthRequest } from '../middleware/auth';
import { HttpError } from '../middleware/errorHandler';
import { db } from '../models/store';
import { ExclusiveContent, SubscriptionTier } from '../types';

const router = Router();

const createContentSchema = z.object({
  title: z.string().min(1).max(150),
  description: z.string().max(500).optional(),
  contentUrl: z.string().url(),
  requiredTier: z.union([z.literal(1), z.literal(2)]),
});

// POST /api/content  — creator publishes exclusive content
router.post('/', requireAuth, (req: AuthRequest, res: Response) => {
  const creatorId = req.userId!;

  const parsed = createContentSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const { title, description, contentUrl, requiredTier } = parsed.data;

  const id = uuidv4();
  const content: ExclusiveContent = {
    id,
    creatorId,
    requiredTier: requiredTier as SubscriptionTier,
    title,
    description: description ?? null,
    contentUrl,
    createdAt: new Date().toISOString(),
  };

  db.exclusiveContent.set(id, content);
  res.status(201).json({ content });
});

// GET /api/content/creator/:creatorId  — list exclusive content for a creator (must be before /:contentId)
router.get('/creator/:creatorId', (req: Request, res: Response) => {
  const { creatorId } = req.params;

  if (!db.users.has(creatorId)) throw new HttpError(404, 'Creator not found');

  const items = [...db.exclusiveContent.values()].filter(
    (c) => c.creatorId === creatorId
  );

  res.json({ items });
});

// GET /api/content/:contentId  — fan accesses content (with entitlement check)
router.get('/:contentId', requireAuth, (req: AuthRequest, res: Response) => {
  const { contentId } = req.params;
  const userId = req.userId!;

  const content = db.exclusiveContent.get(contentId);
  if (!content) throw new HttpError(404, 'Content not found');

  // The creator can always access their own content
  if (content.creatorId === userId) {
    res.json({ content });
    return;
  }

  // Check entitlement
  const key = `${userId}:${content.creatorId}`;
  const entitlement = db.entitlements.get(key);

  if (!entitlement || !entitlement.active) {
    throw new HttpError(403, 'Active subscription required');
  }

  if (entitlement.expiresAt && new Date(entitlement.expiresAt) < new Date()) {
    db.entitlements.set(key, { ...entitlement, active: false });
    throw new HttpError(403, 'Subscription has expired');
  }

  if (entitlement.tier < content.requiredTier) {
    throw new HttpError(
      403,
      `Tier ${content.requiredTier} or higher required (you have tier ${entitlement.tier})`
    );
  }

  res.json({ content });
});

export default router;
