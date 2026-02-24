/**
 * Follow routes — free, no payment required.
 *
 * POST   /api/follow/:creatorId   — follow a creator
 * DELETE /api/follow/:creatorId   — unfollow a creator
 * GET    /api/follow/:creatorId   — check follow status
 */
import { Router, Response } from 'express';
import { requireAuth, AuthRequest } from '../middleware/auth';
import { HttpError } from '../middleware/errorHandler';
import { db } from '../models/store';
import { Follower } from '../types';

const router = Router();

// POST /api/follow/:creatorId
router.post('/:creatorId', requireAuth, (req: AuthRequest, res: Response) => {
  const { creatorId } = req.params;
  const userId = req.userId!;

  if (!db.users.has(creatorId)) throw new HttpError(404, 'Creator not found');
  if (creatorId === userId) throw new HttpError(400, 'Cannot follow yourself');

  const key = `${userId}:${creatorId}`;
  if (db.followers.has(key)) {
    res.status(200).json({ followed: true, message: 'Already following' });
    return;
  }

  const follower: Follower = {
    userId,
    creatorId,
    followedAt: new Date().toISOString(),
  };
  db.followers.set(key, follower);

  res.status(201).json({ followed: true });
});

// DELETE /api/follow/:creatorId
router.delete('/:creatorId', requireAuth, (req: AuthRequest, res: Response) => {
  const { creatorId } = req.params;
  const userId = req.userId!;

  const key = `${userId}:${creatorId}`;
  if (!db.followers.has(key)) throw new HttpError(404, 'Not following this creator');

  db.followers.delete(key);
  res.status(200).json({ followed: false });
});

// GET /api/follow/:creatorId
router.get('/:creatorId', requireAuth, (req: AuthRequest, res: Response) => {
  const { creatorId } = req.params;
  const userId = req.userId!;

  const key = `${userId}:${creatorId}`;
  res.json({ followed: db.followers.has(key) });
});

export default router;
