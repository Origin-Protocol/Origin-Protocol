/**
 * In-memory store used during development.
 *
 * Replace with a real database (PostgreSQL, SQLite …) for production.
 * The interface is intentionally kept simple so that swapping the
 * backing store requires changes only to this file.
 */

import { User, VideoMeta, Comment } from '../types';

export const db = {
  users: new Map<string, User & { passwordHash: string }>(),
  videos: new Map<string, VideoMeta>(),
  comments: new Map<string, Comment>(),
  likes: new Set<string>(), // `${userId}:${videoId}`
};
