// Shared types — keep in sync with server/src/types/index.ts

export interface User {
  id: string;
  username: string;
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

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

// Navigation param-list types
export type RootTabParamList = {
  Feed: undefined;
  Upload: undefined;
  Profile: undefined;
};

export type RootStackParamList = {
  Main: undefined;
  VideoDetail: { videoId: string };
  Login: undefined;
  Register: undefined;
};
