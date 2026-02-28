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
export type Conversation = {
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
};
export type ConversationMemberState = {
    conversationId: string;
    userId: string;
    unreadCount: number;
    lastReadAt: string | null;
    muted: boolean;
    pinned: boolean;
    quietModeUntil?: string | null;
    joinedAt: string;
    role: 'member' | 'owner' | 'moderator' | 'collaborator';
};
export type Message = {
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
};
export type NotificationChannelPreference = 'in_app' | 'in_app_push' | 'off';
export type NotificationCategory = 'dm' | 'video_like' | 'video_comment' | 'comment_reply' | 'social_status' | 'creator_upload' | 'broadcast_post' | 'conversation_reply' | 'system' | 'events';
export type NotificationSettings = {
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
};
export type CreatorNotificationPreference = {
    userId: string;
    creatorId: string;
    upload: NotificationChannelPreference;
    broadcast: NotificationChannelPreference;
    muted: boolean;
    updatedAt: string;
};
export type AppNotification = {
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
};
export type UserBlock = {
    blockerId: string;
    blockedId: string;
    createdAt: string;
};
export type MessageReport = {
    id: string;
    reporterId: string;
    reportedUserId: string;
    messageId: string;
    reason: string;
    createdAt: string;
};
export declare const messagingStore: {
    listConversationsForUser(userId: string): Array<Conversation & {
        memberState: ConversationMemberState;
        unreadCount: number;
    }>;
    listConversationRecipients(conversationId: string): string[];
    getConversationForUser(conversationId: string, userId: string): Conversation;
    createConversation(input: {
        type: ConversationType;
        creatorUserId: string;
        participantIds?: string[];
        title?: string;
        allowReplies?: boolean;
        typingIndicatorsEnabled?: boolean;
        readReceiptsEnabled?: boolean;
        collaboratorIds?: string[];
    }): Conversation;
    subscribeToBroadcast(conversationId: string, userId: string): Conversation;
    unsubscribeFromBroadcast(conversationId: string, userId: string): Conversation;
    listMessages(conversationId: string, userId: string, options?: {
        cursor?: string;
        limit?: number;
    }): {
        items: Message[];
        nextCursor: string | null;
    };
    sendMessage(input: {
        conversationId: string;
        senderId: string;
        content: string;
        attachments?: MessageAttachment[];
        replyToMessageId?: string;
    }): {
        message: Message;
        conversation: Conversation;
        recipientIds: string[];
    };
    reactToMessage(input: {
        messageId: string;
        userId: string;
        emoji: string;
    }): Message;
    markConversationRead(conversationId: string, userId: string): ConversationMemberState;
    updateConversationMemberSettings(input: {
        conversationId: string;
        userId: string;
        muted?: boolean;
        pinned?: boolean;
        quietModeUntil?: string | null;
    }): ConversationMemberState;
    ensureNotificationsSettings(userId: string): NotificationSettings;
    getNotificationSettings(userId: string): NotificationSettings;
    updateNotificationSettings(userId: string, updates: {
        categories?: Partial<Record<NotificationCategory, NotificationChannelPreference>>;
        quietHours?: Partial<NotificationSettings["quietHours"]>;
        experience?: Partial<NotificationSettings["experience"]>;
    }): NotificationSettings;
    getCreatorNotificationPreference(userId: string, creatorId: string): CreatorNotificationPreference;
    updateCreatorNotificationPreference(userId: string, creatorId: string, updates: Partial<Pick<CreatorNotificationPreference, "upload" | "broadcast" | "muted">>): CreatorNotificationPreference;
    listCreatorUploadAudience(creatorId: string): Array<{
        userId: string;
        channel: NotificationChannelPreference;
    }>;
    countFollowersForCreator(creatorId: string): number;
    countFollowingForUser(userId: string): number;
    listFollowersForCreator(creatorId: string): string[];
    listFollowingForUser(userId: string): string[];
    createNotification(input: {
        userId: string;
        type: NotificationCategory;
        title: string;
        body: string;
        data?: Record<string, string>;
        channel?: NotificationChannelPreference;
    }): AppNotification;
    listNotifications(userId: string, options?: {
        cursor?: string;
        limit?: number;
        unreadOnly?: boolean;
    }): {
        items: AppNotification[];
        nextCursor: string | null;
        unreadCount: number;
    };
    markNotificationRead(userId: string, notificationId: string): AppNotification;
    markAllNotificationsRead(userId: string): {
        marked: number;
    };
    blockUser(blockerId: string, blockedId: string): UserBlock;
    unblockUser(blockerId: string, blockedId: string): {
        ok: true;
    };
    listBlockedUsers(blockerId: string): UserBlock[];
    isBlockedEitherDirection(userA: string, userB: string): boolean;
    reportMessage(input: {
        reporterId: string;
        messageId: string;
        reason: string;
    }): MessageReport;
};
//# sourceMappingURL=messagingStore.d.ts.map