import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { requireAuth, AuthRequest } from '../middleware/auth';
import { originService } from '../services/originService';

const router = Router();

const verifySchema = z.object({
  creatorId: z.string(),
  keyId: z.string(),
  assetId: z.string(),
  originId: z.string().optional(),
  contentHash: z.string(),
});

// POST /api/origin/verify
router.post('/verify', requireAuth, async (req: AuthRequest, res: Response) => {
  const parsed = verifySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const result = await originService.verify(parsed.data);
  res.json(result);
});

// GET /api/origin/key-status?creatorId=&keyId=
router.get('/key-status', requireAuth, async (req: Request, res: Response) => {
  const creatorId = (req.query.creatorId as string) ?? '';
  const keyId = (req.query.keyId as string) ?? '';

  if (!creatorId || !keyId) {
    res.status(400).json({ error: 'creatorId and keyId are required' });
    return;
  }

  const result = await originService.keyStatus(creatorId, keyId);
  res.json(result);
});

export default router;
