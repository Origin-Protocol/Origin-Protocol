import { Router, Request, Response } from 'express';
import { db } from '../models/store';

const router = Router();

const DEFAULT_PAGE_SIZE = 20;

// GET /api/feed?page=1&pageSize=20
router.get('/', (req: Request, res: Response) => {
  const page = Math.max(1, parseInt((req.query.page as string) ?? '1', 10));
  const pageSize = Math.min(
    100,
    Math.max(1, parseInt((req.query.pageSize as string) ?? String(DEFAULT_PAGE_SIZE), 10))
  );

  const all = [...db.videos.values()].sort(
    (a, b) => b.createdAt.localeCompare(a.createdAt)
  );

  const total = all.length;
  const start = (page - 1) * pageSize;
  const items = all.slice(start, start + pageSize);

  res.json({
    items,
    total,
    page,
    pageSize,
    hasMore: start + pageSize < total,
  });
});

export default router;
