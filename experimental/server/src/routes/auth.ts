import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt, { SignOptions } from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import { config } from '../config';
import { db } from '../models/store';
import { User } from '../types';

const router = Router();

const registerSchema = z.object({
  username: z.string().min(3).max(32),
  email: z.string().email(),
  password: z.string().min(8),
  displayName: z.string().max(64).optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

// POST /api/auth/register
router.post('/register', async (req: Request, res: Response) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const { username, email, password, displayName } = parsed.data;

  for (const u of db.users.values()) {
    if (u.email === email) {
      res.status(409).json({ error: 'Email already registered' });
      return;
    }
    if (u.username === username) {
      res.status(409).json({ error: 'Username already taken' });
      return;
    }
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const now = new Date().toISOString();
  const id = uuidv4();

  const user: User & { passwordHash: string } = {
    id,
    username,
    email,
    displayName: displayName ?? username,
    avatarUrl: null,
    bio: null,
    creatorKeyId: null,
    createdAt: now,
    passwordHash,
  };

  db.users.set(id, user);

  const token = jwt.sign({ sub: id }, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
  } as SignOptions);

  const { passwordHash: _pw, ...publicUser } = user;
  res.status(201).json({ user: publicUser, token });
});

// POST /api/auth/login
router.post('/login', async (req: Request, res: Response) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.flatten() });
    return;
  }

  const { email, password } = parsed.data;
  const user = [...db.users.values()].find((u) => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  const token = jwt.sign({ sub: user.id }, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn,
  } as SignOptions);

  const { passwordHash: _pw, ...publicUser } = user;
  res.json({ user: publicUser, token });
});

export default router;
