// Shared types mirrored from the server (keep in sync with server/src/types/index.ts)

export interface User {
  id: string;
  username: string;
  displayName: string;
  avatarUrl: string | null;
  bannerPhoto?: string | null;
  bio: string | null;
  headline?: string | null;
  livesIn?: string | null;
  from?: string | null;
  website?: string | null;
  pronouns?: string | null;
  creatorKeyId: string | null;
  createdAt: string;
}

export interface VideoMeta {
  id: string;
  creatorId: string;
  creatorDisplayName?: string;
  creatorUsername?: string;
  creatorAvatarUrl?: string | null;
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
  originReasons?: OriginReason[];
  originVerificationCheckedAt?: string | null;
  createdAt: string;
}

export interface Comment {
  id: string;
  videoId: string;
  authorId: string;
  authorDisplayName?: string;
  authorUsername?: string;
  text: string;
  createdAt: string;
}

export interface OriginReason {
  code: string;
  severity: string;
  message: string;
  platformAction: string;
  creatorAction: string;
}

export interface OriginVerifyResult {
  ok: boolean;
  reasons: OriginReason[];
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

export interface AuthState {
  user: User | null;
  token: string | null;
}

export type ConversationType = 'dm' | 'group' | 'broadcast';

export type MessageAttachment = {
  type: 'origin_video' | 'link';
  videoId?: string;
  url?: string;
  title?: string;
};

export type MessageReaction = {
  emoji: string;
  userIds: string[];
};

export interface ConversationMemberState {
  conversationId: string;
  userId: string;
  unreadCount: number;
  lastReadAt: string | null;
  muted: boolean;
  pinned: boolean;
  quietModeUntil?: string | null;
  joinedAt: string;
  role: 'member' | 'owner' | 'moderator' | 'collaborator';
}

export interface Conversation {
  id: string;
  type: ConversationType;
  title?: string;
  ownerUserId?: string;
  participantIds: string[];
  collaboratorIds: string[];
  subscriberIds: string[];
  allowReplies: boolean;
  typingIndicatorsEnabled: boolean;
  readReceiptsEnabled: boolean;
  createdAt: string;
  updatedAt: string;
  lastMessageAt: string | null;
  lastMessagePreview: string | null;
  memberState?: ConversationMemberState;
  unreadCount?: number;
}

export interface ConversationMessage {
  id: string;
  conversationId: string;
  senderId: string;
  content: string;
  attachments: MessageAttachment[];
  reactions: MessageReaction[];
  replyToMessageId?: string;
  createdAt: string;
  editedAt?: string;
  deletedAt?: string;
}

export type NotificationChannelPreference = 'in_app' | 'in_app_push' | 'off';
export type NotificationCategory =
  | 'dm'
  | 'video_like'
  | 'video_comment'
  | 'comment_reply'
  | 'social_status'
  | 'creator_upload'
  | 'broadcast_post'
  | 'conversation_reply'
  | 'system'
  | 'events';

export interface NotificationSettings {
  userId: string;
  categories: Record<NotificationCategory, NotificationChannelPreference>;
  quietHours: {
    enabled: boolean;
    startHour: number;
    endHour: number;
    timezone?: string;
  };
  experience: {
    showWhyHints: boolean;
  };
  updatedAt: string;
}

export interface CreatorNotificationPreference {
  userId: string;
  creatorId: string;
  upload: NotificationChannelPreference;
  broadcast: NotificationChannelPreference;
  muted: boolean;
  updatedAt: string;
}

export interface AppNotification {
  id: string;
  userId: string;
  type: NotificationCategory;
  title: string;
  body: string;
  data?: Record<string, string>;
  createdAt: string;
  readAt?: string;
  delivery: {
    inApp: boolean;
    pushEligible: boolean;
    pushSuppressedByQuietHours: boolean;
  };
}
