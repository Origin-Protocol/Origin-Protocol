/**
 * In-memory store used during development.
 *
 * Replace with a real database (PostgreSQL, SQLite …) for production.
 * The interface is intentionally kept simple so that swapping the
 * backing store requires changes only to this file.
 */

import { User, VideoMeta, Comment, CreatorSettings, Follower, Subscription, Entitlement, ExclusiveContent } from '../types';

export const db = {
  users: new Map<string, User & { passwordHash: string }>(),
  videos: new Map<string, VideoMeta>(),
  comments: new Map<string, Comment>(),
  likes: new Set<string>(), // `${userId}:${videoId}`

  // ---- Follow / Subscribe system ----
  /** Keyed by creatorId */
  creatorSettings: new Map<string, CreatorSettings>(),
  /** Keyed by `${userId}:${creatorId}` */
  followers: new Map<string, Follower>(),
  /** Keyed by subscription id */
  subscriptions: new Map<string, Subscription>(),
  /** Keyed by `${userId}:${creatorId}` — one entitlement per (user, creator) pair */
  entitlements: new Map<string, Entitlement>(),
  /** Keyed by content id */
  exclusiveContent: new Map<string, ExclusiveContent>(),
};
