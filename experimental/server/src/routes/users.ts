import { Router, Response } from 'express';
import { z } from 'zod';
import { requireAuth, AuthRequest } from '../middleware/auth';
import { HttpError } from '../middleware/errorHandler';
import { db } from '../models/store';

const router = Router();

const updateSchema = z.object({
  displayName: z.string().max(64).optional(),
  bio: z.string().max(280).optional(),
  creatorKeyId: z.string().max(256).optional(),
});

// GET /api/users/:id
router.get('/:id', (req: AuthRequest, res: Response) => {
  const user = db.users.get(req.params.id);
  if (!user) throw new HttpError(404, 'User not found');

  const { passwordHash: _pw, email: _email, ...publicUser } = user;
  res.json({ user: publicUser });
});

// PATCH /api/users/me
router.patch('/me', requireAuth, (req: AuthRequest, res: Response) => {
  const user = db.users.get(req.userId!);
  if (!user) throw new HttpError(404, 'User not found');

  const parsed = updateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const updated = { ...user, ...parsed.data };
  db.users.set(user.id, updated);

  const { passwordHash: _pw, email: _email, ...publicUser } = updated;
  res.json({ user: publicUser });
});

export default router;
