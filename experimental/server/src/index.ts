import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import { config } from './config';
import { errorHandler } from './middleware/errorHandler';
import authRouter from './routes/auth';
import usersRouter from './routes/users';
import videosRouter from './routes/videos';
import feedRouter from './routes/feed';
import originRouter from './routes/origin';

const app = express();

// --- Security & logging middleware ---
app.use(helmet());
app.use(
  cors({
    origin: config.nodeEnv === 'production' ? process.env.ALLOWED_ORIGINS?.split(',') : '*',
    credentials: true,
  })
);
app.use(morgan(config.nodeEnv === 'production' ? 'combined' : 'dev'));

// --- Rate limiting ---
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// --- Body parsing ---
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// --- Static uploads ---
const uploadsDir = path.resolve(config.storage.localDir);
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// --- Routes ---
app.use('/api/auth', authRouter);
app.use('/api/users', usersRouter);
app.use('/api/videos', videosRouter);
app.use('/api/feed', feedRouter);
app.use('/api/origin', originRouter);

// --- Health check ---
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// --- Error handler (must be last) ---
app.use(errorHandler);

// --- Start ---
app.listen(config.port, () => {
  console.log(`[origin-social/server] listening on http://localhost:${config.port}`);
});

export default app;
