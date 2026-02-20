import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import { requireAuth, AuthRequest } from '../middleware/auth';
import { HttpError } from '../middleware/errorHandler';
import { db } from '../models/store';
import { originService } from '../services/originService';
import { config } from '../config';

const router = Router();

// Local disk storage; swap with S3 middleware in production
const storage = multer.diskStorage({
  destination: config.storage.localDir,
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB
  fileFilter: (_req, file, cb) => {
    const allowed = ['video/mp4', 'video/quicktime', 'video/webm'];
    cb(null, allowed.includes(file.mimetype));
  },
});

const uploadSchema = z.object({
  title: z.string().min(1).max(150),
  description: z.string().max(500).optional(),
  originBundleId: z.string().optional(),
});

// GET /api/videos/:id
router.get('/:id', (req: Request, res: Response) => {
  const video = db.videos.get(req.params.id);
  if (!video) throw new HttpError(404, 'Video not found');
  // Increment view count
  const updated = { ...video, viewCount: video.viewCount + 1 };
  db.videos.set(video.id, updated);
  res.json({ video: updated });
});

// POST /api/videos  (requires auth + video file)
router.post(
  '/',
  requireAuth,
  upload.single('video'),
  async (req: AuthRequest, res: Response) => {
    if (!req.file) throw new HttpError(400, 'No video file provided');

    const parsed = uploadSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.flatten() });
      return;
    }

    const { title, description, originBundleId } = parsed.data;
    const creatorId = req.userId!;
    const creator = db.users.get(creatorId);

    let originVerified = false;

    // If the creator supplied an Origin bundle reference, verify it
    if (originBundleId && creator?.creatorKeyId) {
      try {
        const result = await originService.verify({
          creatorId,
          keyId: creator.creatorKeyId,
          assetId: originBundleId,
          contentHash: req.file.filename,
        });
        originVerified = result.ok;
      } catch {
        // Ledger unreachable — allow upload but mark unverified
        originVerified = false;
      }
    }

    const now = new Date().toISOString();
    const id = uuidv4();
    const videoUrl = `/uploads/${req.file.filename}`;

    const video = {
      id,
      creatorId,
      title,
      description: description ?? null,
      videoUrl,
      thumbnailUrl: null,
      duration: null,
      likeCount: 0,
      commentCount: 0,
      viewCount: 0,
      originBundleId: originBundleId ?? null,
      originVerified,
      createdAt: now,
    };

    db.videos.set(id, video);
    res.status(201).json({ video });
  }
);

// DELETE /api/videos/:id
router.delete('/:id', requireAuth, (req: AuthRequest, res: Response) => {
  const video = db.videos.get(req.params.id);
  if (!video) throw new HttpError(404, 'Video not found');
  if (video.creatorId !== req.userId) throw new HttpError(403, 'Forbidden');

  db.videos.delete(video.id);
  res.status(204).send();
});

// POST /api/videos/:id/like
router.post('/:id/like', requireAuth, (req: AuthRequest, res: Response) => {
  const video = db.videos.get(req.params.id);
  if (!video) throw new HttpError(404, 'Video not found');

  const key = `${req.userId}:${video.id}`;
  const liked = db.likes.has(key);

  if (liked) {
    db.likes.delete(key);
    db.videos.set(video.id, { ...video, likeCount: Math.max(0, video.likeCount - 1) });
    res.json({ liked: false });
  } else {
    db.likes.add(key);
    db.videos.set(video.id, { ...video, likeCount: video.likeCount + 1 });
    res.json({ liked: true });
  }
});

// GET /api/videos/:id/comments
router.get('/:id/comments', (req: Request, res: Response) => {
  const video = db.videos.get(req.params.id);
  if (!video) throw new HttpError(404, 'Video not found');

  const comments = [...db.comments.values()]
    .filter((c) => c.videoId === video.id)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt));

  res.json({ comments });
});

// POST /api/videos/:id/comments
router.post('/:id/comments', requireAuth, (req: AuthRequest, res: Response) => {
  const video = db.videos.get(req.params.id);
  if (!video) throw new HttpError(404, 'Video not found');

  const text = (req.body?.text ?? '').toString().trim();
  if (!text || text.length > 500) {
    res.status(400).json({ error: 'Comment text must be 1–500 characters' });
    return;
  }

  const id = uuidv4();
  const comment = {
    id,
    videoId: video.id,
    authorId: req.userId!,
    text,
    createdAt: new Date().toISOString(),
  };

  db.comments.set(id, comment);
  db.videos.set(video.id, { ...video, commentCount: video.commentCount + 1 });
  res.status(201).json({ comment });
});

export default router;
