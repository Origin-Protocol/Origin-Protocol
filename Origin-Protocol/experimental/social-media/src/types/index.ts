// Shared types mirrored from the server (keep in sync with server/src/types/index.ts)

export interface User {
  id: string;
  username: string;
  displayName: string;
  avatarUrl: string | null;
  bannerPhoto?: string | null;
  bio: string | null;
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
  originPolicy?: string | null;
  governanceLedgerCid?: string | null;
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

export type MessageReadReceipt = {
  userId: string;
  readAt: string;
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
  sentAt?: string;
  deliveredTo?: string[];
  readBy?: MessageReadReceipt[];
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

export interface LiveSession {
  id: string;
  hostUserId: string;
  hostDisplayName: string;
  hostUsername: string;
  title: string;
  description: string | null;
  status: 'live' | 'ended';
  startedAt: string;
  endedAt: string | null;
  viewerCount: number;
  peakViewerCount: number;
  likeCount: number;
  likedByMe: boolean;
  commentCount: number;
}

export interface LiveComment {
  id: string;
  sessionId: string;
  authorId: string;
  authorDisplayName: string;
  authorUsername: string;
  text: string;
  createdAt: string;
  parentId: string | null;
  likeCount: number;
  likedByMe: boolean;
  replies: LiveComment[];
}

export interface LiveEligibility {
  eligible: boolean;
  isAdminBypass?: boolean;
  metrics: {
    followers: number;
    totalViews: number;
    publishedVideos: number;
    verifiedVideos: number;
  };
  requirements: {
    minFollowers: number;
    minTotalViews: number;
    minPublishedVideos: number;
    minVerifiedVideos: number;
  };
  unmet: string[];
  activeSession?: LiveSession | null;
}

export interface AbigailProfileSettings {
  tone: string;
  boundaries: string;
  goals: string;
}

export interface AbigailChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  createdAt: string;
}

export interface AbigailMemoryEvent {
  id: string;
  type: 'watch' | 'search' | 'save' | 'like' | 'goal' | 'preference' | 'note';
  title: string;
  detail?: string;
  createdAt: string;
}

export interface AbigailRecommendation {
  id: string;
  kind: 'video' | 'article' | 'task';
  title: string;
  reason: string;
  href?: string;
}

export interface SocialSignal {
  id: string;
  platform: 'youtube' | 'tiktok' | 'x';
  type: 'watch' | 'search' | 'save' | 'like';
  title: string;
  createdAt: string;
}

export interface UserSettings {
  userId: string;
  personalInformation: {
    displayName: string;
    username: string;
    bio: string;
    profilePhoto: string;
    bannerPhoto: string;
    pronouns: string;
    birthday: string;
    location: string;
    contactEmail: string;
    phoneNumber: string;
  };
  privacySafety: {
    whoCanMessageMe: 'everyone' | 'friends' | 'followers' | 'no_one';
    whoCanSeeMyPosts: 'public' | 'followers' | 'private';
    blockedUsers: string[];
    mutedUsers: string[];
    twoFactorAuthEnabled: boolean;
    loginAlertsEnabled: boolean;
    pauseAbigailMemoryCollection: boolean;
  };
  preferences: {
    notificationMode: 'all' | 'important' | 'minimal';
    feedTuning: 'balanced' | 'following_first' | 'discovery_first';
    contentPreferences: string[];
    theme: 'dark' | 'light' | 'system';
    language: string;
    sensitiveContent: 'strict' | 'moderate' | 'permissive';
    abigailTone: 'professional' | 'casual' | 'concise' | 'detailed';
  };
  billingPurchases: {
    subscriptions: Array<{ id: string; name: string; status: 'active' | 'paused' | 'canceled'; renewalAt?: string }>;
    paymentMethods: Array<{ id: string; brand: string; last4: string; expMonth: number; expYear: number }>;
    billingHistory: Array<{ id: string; amountUsd: number; createdAt: string; description: string }>;
    receipts: Array<{ id: string; title: string; url: string; createdAt: string }>;
    autoRenewEnabled: boolean;
  };
  devicesSessions: {
    activeSessions: Array<{
      id: string;
      deviceName: string;
      location: string;
      ipAddress: string;
      lastSeenAt: string;
      current: boolean;
    }>;
    deviceList: Array<{
      id: string;
      deviceName: string;
      location: string;
      ipAddress: string;
      lastSeenAt: string;
      current: boolean;
    }>;
    loginHistory: Array<{
      id: string;
      deviceName: string;
      location: string;
      ipAddress: string;
      createdAt: string;
    }>;
  };
  abigailPersonalization: {
    userGoals: string[];
    habits: string[];
    interests: string[];
    learningStyle: string;
    memorySummary: string;
  };
  accountManagement: {
    legalAgreementsAcceptedAt: string;
    ageVerificationStatus: 'unverified' | 'pending' | 'verified';
  };
  updatedAt: string;
}

export interface AbigailMemorySummary {
  profile?: {
    preferredTone?: string;
    pacing?: string;
    goals?: string[];
    traits?: string[];
    topics?: string[];
  } | null;
  events: AbigailMemoryEvent[];
  memories?: Array<{
    id: string;
    type: string;
    key: string;
    value: string;
    summary: string;
    importance: number;
    createdAt: string;
    updatedAt: string;
  }>;
}
