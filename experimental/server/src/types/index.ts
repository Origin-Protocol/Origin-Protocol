// Shared TypeScript types used across the server

export interface User {
  id: string;
  username: string;
  email: string;
  displayName: string;
  avatarUrl: string | null;
  bio: string | null;
  creatorKeyId: string | null;
  createdAt: string;
}

export interface VideoMeta {
  id: string;
  creatorId: string;
  title: string;
  description: string | null;
  videoUrl: string;
  thumbnailUrl: string | null;
  duration: number | null;
  likeCount: number;
  commentCount: number;
  viewCount: number;
  originBundleId: string | null;
  originVerified: boolean;
  createdAt: string;
}

export interface Comment {
  id: string;
  videoId: string;
  authorId: string;
  text: string;
  createdAt: string;
}

export interface OriginVerifyResult {
  ok: boolean;
  reasons: OriginReason[];
}

export interface OriginReason {
  code: string;
  severity: string;
  message: string;
  platformAction: string;
  creatorAction: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

// Request bodies

export interface RegisterBody {
  username: string;
  email: string;
  password: string;
  displayName?: string;
}

export interface LoginBody {
  email: string;
  password: string;
}

export interface UploadVideoBody {
  title: string;
  description?: string;
  originBundleId?: string;
}

export interface PostCommentBody {
  text: string;
}

export interface UpdateProfileBody {
  displayName?: string;
  bio?: string;
  creatorKeyId?: string;
}

// ---- Follow / Subscribe system ----

/** Tier 0 = free follow; 1 = Basic Subscriber; 2 = Super Fan */
export type SubscriptionTier = 0 | 1 | 2;

export interface CreatorSettings {
  creatorId: string;
  subscriptionsEnabled: boolean;
  /** Price in cents (USD) for Basic tier */
  basicPriceCents: number;
  /** Price in cents (USD) for Super Fan tier */
  superFanPriceCents: number;
  /** Stripe product ID (set after Stripe sync) */
  stripeProductId: string | null;
  /** Stripe price IDs keyed by tier */
  stripePriceIds: { basic: string | null; superFan: string | null };
}

export interface Follower {
  userId: string;
  creatorId: string;
  followedAt: string;
}

export interface Subscription {
  id: string;
  userId: string;
  creatorId: string;
  tier: SubscriptionTier;
  active: boolean;
  expiresAt: string | null;
  stripeSubscriptionId: string | null;
  createdAt: string;
}

/** Entitlement record — the authoritative source for content access checks. */
export interface Entitlement {
  userId: string;
  creatorId: string;
  tier: SubscriptionTier;
  active: boolean;
  expiresAt: string | null;
}

export interface ExclusiveContent {
  id: string;
  creatorId: string;
  /** Minimum tier required to access this content */
  requiredTier: SubscriptionTier;
  title: string;
  description: string | null;
  contentUrl: string;
  createdAt: string;
}

// Request bodies for the Follow / Subscribe routes

export interface CreatorSettingsBody {
  subscriptionsEnabled?: boolean;
  basicPriceCents?: number;
  superFanPriceCents?: number;
}

export interface SubscribeBody {
  /** 1 = Basic, 2 = Super Fan */
  tier: 1 | 2;
  /** Optional payment method ID from Stripe.js */
  stripePaymentMethodId?: string;
}

export interface ExclusiveContentBody {
  title: string;
  description?: string;
  requiredTier: 1 | 2;
}
