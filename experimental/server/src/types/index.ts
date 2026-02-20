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
