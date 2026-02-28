"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.messagingStore = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const errorHandler_1 = require("../middleware/errorHandler");
const DATA_DIR = path_1.default.resolve('.data');
const STORE_FILE = path_1.default.join(DATA_DIR, 'messaging.json');
const MAX_NOTIFICATIONS_PER_USER = 500;
const MAX_REPORTS = 5000;
function defaultNotificationSettings(userId) {
    return {
        userId,
        categories: {
            dm: 'in_app_push',
            video_like: 'in_app',
            video_comment: 'in_app',
            comment_reply: 'in_app_push',
            social_status: 'in_app',
            creator_upload: 'in_app',
            broadcast_post: 'in_app',
            conversation_reply: 'in_app',
            system: 'in_app_push',
            events: 'in_app',
        },
        quietHours: {
            enabled: false,
            startHour: 23,
            endHour: 8,
        },
        experience: {
            showWhyHints: true,
        },
        updatedAt: new Date().toISOString(),
    };
}
function id(prefix) {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}
function ensureDataDir() {
    if (!fs_1.default.existsSync(DATA_DIR)) {
        fs_1.default.mkdirSync(DATA_DIR, { recursive: true });
    }
}
function load() {
    try {
        if (!fs_1.default.existsSync(STORE_FILE)) {
            return {
                conversations: [],
                memberStates: [],
                messages: [],
                notifications: [],
                notificationSettings: [],
                creatorNotificationPreferences: [],
                blocks: [],
                reports: [],
                counters: [],
            };
        }
        const raw = fs_1.default.readFileSync(STORE_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return {
            conversations: Array.isArray(parsed.conversations) ? parsed.conversations : [],
            memberStates: Array.isArray(parsed.memberStates) ? parsed.memberStates : [],
            messages: Array.isArray(parsed.messages) ? parsed.messages : [],
            notifications: Array.isArray(parsed.notifications) ? parsed.notifications : [],
            notificationSettings: Array.isArray(parsed.notificationSettings) ? parsed.notificationSettings : [],
            creatorNotificationPreferences: Array.isArray(parsed.creatorNotificationPreferences)
                ? parsed.creatorNotificationPreferences
                : [],
            blocks: Array.isArray(parsed.blocks) ? parsed.blocks : [],
            reports: Array.isArray(parsed.reports) ? parsed.reports : [],
            counters: Array.isArray(parsed.counters) ? parsed.counters : [],
        };
    }
    catch {
        return {
            conversations: [],
            memberStates: [],
            messages: [],
            notifications: [],
            notificationSettings: [],
            creatorNotificationPreferences: [],
            blocks: [],
            reports: [],
            counters: [],
        };
    }
}
function save(payload) {
    ensureDataDir();
    fs_1.default.writeFileSync(STORE_FILE, JSON.stringify(payload, null, 2), 'utf8');
}
function isWithinQuietHours(settings, now = new Date()) {
    if (!settings.quietHours.enabled)
        return false;
    const hour = now.getHours();
    const { startHour, endHour } = settings.quietHours;
    if (startHour === endHour)
        return true;
    if (startHour < endHour) {
        return hour >= startHour && hour < endHour;
    }
    return hour >= startHour || hour < endHour;
}
function normalizeParticipants(participantIds) {
    return [...new Set(participantIds.map((x) => x.trim()).filter(Boolean))];
}
function sameDmParticipants(a, b) {
    if (a.length !== b.length)
        return false;
    const sa = [...a].sort();
    const sb = [...b].sort();
    return sa.every((value, idx) => value === sb[idx]);
}
function getCounter(payload, userId) {
    let item = payload.counters.find((entry) => entry.userId === userId);
    if (!item) {
        item = {
            userId,
            messageSentAt: [],
            conversationCreatedAt: [],
        };
        payload.counters.push(item);
    }
    return item;
}
function assertMessageRateLimit(payload, userId) {
    const counter = getCounter(payload, userId);
    const now = Date.now();
    const minuteAgo = now - 60000;
    const hourAgo = now - 3600000;
    counter.messageSentAt = counter.messageSentAt.filter((iso) => Date.parse(iso) >= hourAgo);
    const perMinute = counter.messageSentAt.filter((iso) => Date.parse(iso) >= minuteAgo).length;
    const perHour = counter.messageSentAt.length;
    if (perMinute >= 25) {
        throw new errorHandler_1.HttpError(429, 'Messaging rate limit exceeded (per-minute). Please slow down.');
    }
    if (perHour >= 300) {
        throw new errorHandler_1.HttpError(429, 'Messaging rate limit exceeded (per-hour). Please slow down.');
    }
    counter.messageSentAt.push(new Date(now).toISOString());
}
function assertConversationCreateLimit(payload, userId) {
    const counter = getCounter(payload, userId);
    const now = Date.now();
    const dayAgo = now - 86400000;
    counter.conversationCreatedAt = counter.conversationCreatedAt.filter((iso) => Date.parse(iso) >= dayAgo);
    if (counter.conversationCreatedAt.length >= 30) {
        throw new errorHandler_1.HttpError(429, 'Conversation creation limit reached for today.');
    }
    counter.conversationCreatedAt.push(new Date(now).toISOString());
}
function ensureMemberState(payload, conversationId, userId, role = 'member') {
    let state = payload.memberStates.find((item) => item.conversationId === conversationId && item.userId === userId);
    if (!state) {
        state = {
            conversationId,
            userId,
            unreadCount: 0,
            lastReadAt: null,
            muted: false,
            pinned: false,
            joinedAt: new Date().toISOString(),
            role,
            quietModeUntil: null,
        };
        payload.memberStates.push(state);
    }
    return state;
}
function userCanAccessConversation(conversation, userId) {
    if (conversation.type === 'broadcast') {
        return (conversation.ownerUserId === userId
            || conversation.collaboratorIds.includes(userId)
            || conversation.subscriberIds.includes(userId));
    }
    return conversation.participantIds.includes(userId);
}
function userCanPostConversation(conversation, userId) {
    if (conversation.type === 'broadcast') {
        if (conversation.ownerUserId === userId)
            return true;
        if (conversation.collaboratorIds.includes(userId))
            return true;
        if (conversation.allowReplies && conversation.subscriberIds.includes(userId))
            return true;
        return false;
    }
    return conversation.participantIds.includes(userId);
}
function updateMemberRole(conversation, userId) {
    if (conversation.ownerUserId === userId)
        return 'owner';
    if (conversation.collaboratorIds.includes(userId))
        return 'collaborator';
    return 'member';
}
function updateNotificationCap(payload, userId) {
    const userItems = payload.notifications
        .filter((item) => item.userId === userId)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    if (userItems.length <= MAX_NOTIFICATIONS_PER_USER) {
        return;
    }
    const toKeep = new Set(userItems.slice(0, MAX_NOTIFICATIONS_PER_USER).map((item) => item.id));
    payload.notifications = payload.notifications.filter((item) => item.userId !== userId || toKeep.has(item.id));
}
exports.messagingStore = {
    listConversationsForUser(userId) {
        const payload = load();
        return payload.conversations
            .filter((conversation) => {
            if (!userCanAccessConversation(conversation, userId))
                return false;
            if (conversation.type !== 'dm')
                return true;
            const blockedIds = payload.blocks
                .filter((item) => item.blockerId === userId)
                .map((item) => item.blockedId);
            const otherParticipant = conversation.participantIds.find((idValue) => idValue !== userId);
            if (!otherParticipant)
                return true;
            return !blockedIds.includes(otherParticipant);
        })
            .map((conversation) => {
            const state = ensureMemberState(payload, conversation.id, userId, updateMemberRole(conversation, userId));
            return {
                ...conversation,
                memberState: state,
                unreadCount: state.unreadCount,
            };
        })
            .sort((a, b) => {
            if (a.memberState.pinned !== b.memberState.pinned) {
                return a.memberState.pinned ? -1 : 1;
            }
            if (a.unreadCount !== b.unreadCount) {
                return b.unreadCount - a.unreadCount;
            }
            return (b.lastMessageAt ?? b.updatedAt).localeCompare(a.lastMessageAt ?? a.updatedAt);
        });
    },
    listConversationRecipients(conversationId) {
        const payload = load();
        const conversation = payload.conversations.find((item) => item.id === conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        const recipients = new Set();
        if (conversation.type === 'broadcast') {
            conversation.subscriberIds.forEach((userId) => recipients.add(userId));
            conversation.collaboratorIds.forEach((userId) => recipients.add(userId));
            if (conversation.ownerUserId)
                recipients.add(conversation.ownerUserId);
        }
        else {
            conversation.participantIds.forEach((userId) => recipients.add(userId));
        }
        return [...recipients];
    },
    getConversationForUser(conversationId, userId) {
        const payload = load();
        const conversation = payload.conversations.find((item) => item.id === conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        if (!userCanAccessConversation(conversation, userId))
            throw new errorHandler_1.HttpError(403, 'Forbidden');
        return conversation;
    },
    createConversation(input) {
        const payload = load();
        assertConversationCreateLimit(payload, input.creatorUserId);
        const now = new Date().toISOString();
        const type = input.type;
        if (type === 'dm') {
            const participantIds = normalizeParticipants([input.creatorUserId, ...(input.participantIds ?? [])]);
            if (participantIds.length !== 2) {
                throw new errorHandler_1.HttpError(400, 'Direct messages must have exactly 2 participants.');
            }
            const existing = payload.conversations.find((conversation) => conversation.type === 'dm' && sameDmParticipants(conversation.participantIds, participantIds));
            if (existing) {
                return existing;
            }
            const created = {
                id: id('conv'),
                type: 'dm',
                participantIds,
                collaboratorIds: [],
                subscriberIds: [],
                allowReplies: false,
                typingIndicatorsEnabled: Boolean(input.typingIndicatorsEnabled ?? true),
                readReceiptsEnabled: Boolean(input.readReceiptsEnabled ?? false),
                createdAt: now,
                updatedAt: now,
                lastMessageAt: null,
                lastMessagePreview: null,
            };
            payload.conversations.push(created);
            for (const participantId of participantIds) {
                ensureMemberState(payload, created.id, participantId, 'member');
            }
            save(payload);
            return created;
        }
        if (type === 'group') {
            const participantIds = normalizeParticipants([input.creatorUserId, ...(input.participantIds ?? [])]);
            if (participantIds.length < 3 || participantIds.length > 25) {
                throw new errorHandler_1.HttpError(400, 'Group chats must have 3-25 participants.');
            }
            const created = {
                id: id('conv'),
                type: 'group',
                title: input.title?.trim() || 'Group chat',
                ownerUserId: input.creatorUserId,
                participantIds,
                collaboratorIds: [],
                subscriberIds: [],
                allowReplies: true,
                typingIndicatorsEnabled: Boolean(input.typingIndicatorsEnabled ?? true),
                readReceiptsEnabled: Boolean(input.readReceiptsEnabled ?? false),
                createdAt: now,
                updatedAt: now,
                lastMessageAt: null,
                lastMessagePreview: null,
            };
            payload.conversations.push(created);
            for (const participantId of participantIds) {
                ensureMemberState(payload, created.id, participantId, participantId === input.creatorUserId ? 'owner' : 'member');
            }
            save(payload);
            return created;
        }
        const collaborators = normalizeParticipants(input.collaboratorIds ?? []).filter((userId) => userId !== input.creatorUserId);
        const created = {
            id: id('conv'),
            type: 'broadcast',
            title: input.title?.trim() || 'Broadcast channel',
            ownerUserId: input.creatorUserId,
            participantIds: [input.creatorUserId],
            collaboratorIds: collaborators,
            subscriberIds: [input.creatorUserId, ...collaborators],
            allowReplies: Boolean(input.allowReplies ?? false),
            typingIndicatorsEnabled: false,
            readReceiptsEnabled: false,
            createdAt: now,
            updatedAt: now,
            lastMessageAt: null,
            lastMessagePreview: null,
        };
        payload.conversations.push(created);
        ensureMemberState(payload, created.id, input.creatorUserId, 'owner');
        for (const collaborator of collaborators) {
            ensureMemberState(payload, created.id, collaborator, 'collaborator');
        }
        save(payload);
        return created;
    },
    subscribeToBroadcast(conversationId, userId) {
        const payload = load();
        const conversation = payload.conversations.find((item) => item.id === conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        if (conversation.type !== 'broadcast')
            throw new errorHandler_1.HttpError(400, 'Only broadcast channels can be subscribed.');
        if (!conversation.subscriberIds.includes(userId)) {
            conversation.subscriberIds.push(userId);
            conversation.updatedAt = new Date().toISOString();
        }
        ensureMemberState(payload, conversation.id, userId, updateMemberRole(conversation, userId));
        save(payload);
        return conversation;
    },
    unsubscribeFromBroadcast(conversationId, userId) {
        const payload = load();
        const conversation = payload.conversations.find((item) => item.id === conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        if (conversation.type !== 'broadcast')
            throw new errorHandler_1.HttpError(400, 'Only broadcast channels can be unsubscribed.');
        if (conversation.ownerUserId === userId)
            throw new errorHandler_1.HttpError(400, 'Creator cannot unsubscribe from own channel.');
        conversation.subscriberIds = conversation.subscriberIds.filter((idValue) => idValue !== userId);
        conversation.updatedAt = new Date().toISOString();
        save(payload);
        return conversation;
    },
    listMessages(conversationId, userId, options) {
        const payload = load();
        const conversation = payload.conversations.find((item) => item.id === conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        if (!userCanAccessConversation(conversation, userId))
            throw new errorHandler_1.HttpError(403, 'Forbidden');
        const limit = Math.max(1, Math.min(Number(options?.limit ?? 40), 100));
        const all = payload.messages
            .filter((item) => item.conversationId === conversationId && !item.deletedAt)
            .map((item) => ({
            ...item,
            sentAt: item.sentAt ?? item.createdAt,
            deliveredTo: Array.isArray(item.deliveredTo) ? item.deliveredTo : [],
            readBy: Array.isArray(item.readBy) ? item.readBy : [],
        }))
            .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
        if (all.length === 0) {
            return { items: [], nextCursor: null };
        }
        if (!options?.cursor) {
            const start = Math.max(0, all.length - limit);
            const items = all.slice(start);
            const nextCursor = start > 0 ? all[start - 1].id : null;
            return { items, nextCursor };
        }
        const idx = all.findIndex((item) => item.id === options.cursor);
        if (idx < 0) {
            const start = Math.max(0, all.length - limit);
            const items = all.slice(start);
            const nextCursor = start > 0 ? all[start - 1].id : null;
            return { items, nextCursor };
        }
        const start = Math.max(0, idx - limit);
        const items = all.slice(start, idx);
        const nextCursor = start > 0 ? all[start - 1].id : null;
        return { items, nextCursor };
    },
    sendMessage(input) {
        const payload = load();
        const conversation = payload.conversations.find((item) => item.id === input.conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        if (!userCanPostConversation(conversation, input.senderId)) {
            throw new errorHandler_1.HttpError(403, 'You cannot post in this conversation.');
        }
        const trimmed = input.content.trim();
        if (!trimmed && !(input.attachments && input.attachments.length > 0)) {
            throw new errorHandler_1.HttpError(400, 'Message content or attachments are required.');
        }
        assertMessageRateLimit(payload, input.senderId);
        const now = new Date().toISOString();
        const message = {
            id: id('msg'),
            conversationId: conversation.id,
            senderId: input.senderId,
            content: trimmed,
            attachments: (input.attachments ?? []).slice(0, 6),
            reactions: [],
            sentAt: now,
            deliveredTo: [],
            readBy: [{ userId: input.senderId, readAt: now }],
            replyToMessageId: input.replyToMessageId,
            createdAt: now,
        };
        payload.messages.push(message);
        conversation.updatedAt = now;
        conversation.lastMessageAt = now;
        conversation.lastMessagePreview = trimmed ? trimmed.slice(0, 220) : '[media]';
        const recipients = new Set();
        if (conversation.type === 'broadcast') {
            conversation.subscriberIds.forEach((userId) => recipients.add(userId));
            conversation.collaboratorIds.forEach((userId) => recipients.add(userId));
            if (conversation.ownerUserId)
                recipients.add(conversation.ownerUserId);
        }
        else {
            conversation.participantIds.forEach((userId) => recipients.add(userId));
        }
        recipients.delete(input.senderId);
        message.deliveredTo = [...recipients];
        for (const recipientId of recipients) {
            const state = ensureMemberState(payload, conversation.id, recipientId, updateMemberRole(conversation, recipientId));
            state.unreadCount += 1;
        }
        const senderState = ensureMemberState(payload, conversation.id, input.senderId, updateMemberRole(conversation, input.senderId));
        senderState.unreadCount = 0;
        senderState.lastReadAt = now;
        save(payload);
        return {
            message,
            conversation,
            recipientIds: [...recipients],
        };
    },
    reactToMessage(input) {
        const payload = load();
        const message = payload.messages.find((item) => item.id === input.messageId && !item.deletedAt);
        if (!message)
            throw new errorHandler_1.HttpError(404, 'Message not found');
        const conversation = payload.conversations.find((item) => item.id === message.conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        if (!userCanAccessConversation(conversation, input.userId))
            throw new errorHandler_1.HttpError(403, 'Forbidden');
        const emoji = input.emoji.trim();
        if (!emoji)
            throw new errorHandler_1.HttpError(400, 'Emoji is required');
        let reaction = message.reactions.find((item) => item.emoji === emoji);
        if (!reaction) {
            reaction = { emoji, userIds: [] };
            message.reactions.push(reaction);
        }
        if (reaction.userIds.includes(input.userId)) {
            reaction.userIds = reaction.userIds.filter((idValue) => idValue !== input.userId);
            if (reaction.userIds.length === 0) {
                message.reactions = message.reactions.filter((item) => item.emoji !== emoji);
            }
        }
        else {
            reaction.userIds.push(input.userId);
        }
        save(payload);
        return message;
    },
    markConversationRead(conversationId, userId) {
        const payload = load();
        const conversation = payload.conversations.find((item) => item.id === conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        if (!userCanAccessConversation(conversation, userId))
            throw new errorHandler_1.HttpError(403, 'Forbidden');
        const state = ensureMemberState(payload, conversationId, userId, updateMemberRole(conversation, userId));
        const readAt = new Date().toISOString();
        state.unreadCount = 0;
        state.lastReadAt = readAt;
        for (const message of payload.messages) {
            if (message.conversationId !== conversationId || message.deletedAt || message.senderId === userId) {
                continue;
            }
            if (!Array.isArray(message.readBy)) {
                message.readBy = [];
            }
            if (!message.readBy.some((entry) => entry.userId === userId)) {
                message.readBy.push({ userId, readAt });
            }
        }
        save(payload);
        return state;
    },
    updateConversationMemberSettings(input) {
        const payload = load();
        const conversation = payload.conversations.find((item) => item.id === input.conversationId);
        if (!conversation)
            throw new errorHandler_1.HttpError(404, 'Conversation not found');
        if (!userCanAccessConversation(conversation, input.userId))
            throw new errorHandler_1.HttpError(403, 'Forbidden');
        const state = ensureMemberState(payload, input.conversationId, input.userId, updateMemberRole(conversation, input.userId));
        if (typeof input.muted === 'boolean')
            state.muted = input.muted;
        if (typeof input.pinned === 'boolean')
            state.pinned = input.pinned;
        if (typeof input.quietModeUntil === 'string' || input.quietModeUntil === null) {
            state.quietModeUntil = input.quietModeUntil;
        }
        save(payload);
        return state;
    },
    ensureNotificationsSettings(userId) {
        const payload = load();
        let settings = payload.notificationSettings.find((item) => item.userId === userId);
        if (!settings) {
            settings = defaultNotificationSettings(userId);
            payload.notificationSettings.push(settings);
            save(payload);
            return settings;
        }
        const defaults = defaultNotificationSettings(userId);
        settings.categories = {
            ...defaults.categories,
            ...settings.categories,
        };
        settings.quietHours = {
            ...defaults.quietHours,
            ...settings.quietHours,
        };
        settings.experience = {
            ...defaults.experience,
            ...settings.experience,
        };
        save(payload);
        return settings;
    },
    getNotificationSettings(userId) {
        return this.ensureNotificationsSettings(userId);
    },
    updateNotificationSettings(userId, updates) {
        const payload = load();
        let settings = payload.notificationSettings.find((item) => item.userId === userId);
        if (!settings) {
            settings = defaultNotificationSettings(userId);
            payload.notificationSettings.push(settings);
        }
        if (updates.categories) {
            settings.categories = {
                ...settings.categories,
                ...updates.categories,
            };
        }
        if (updates.quietHours) {
            settings.quietHours = {
                ...settings.quietHours,
                ...updates.quietHours,
            };
        }
        if (updates.experience) {
            settings.experience = {
                ...settings.experience,
                ...updates.experience,
            };
        }
        settings.updatedAt = new Date().toISOString();
        save(payload);
        return settings;
    },
    getCreatorNotificationPreference(userId, creatorId) {
        const payload = load();
        let pref = payload.creatorNotificationPreferences.find((item) => item.userId === userId && item.creatorId === creatorId);
        if (!pref) {
            pref = {
                userId,
                creatorId,
                upload: 'in_app',
                broadcast: 'in_app',
                muted: false,
                updatedAt: new Date().toISOString(),
            };
            payload.creatorNotificationPreferences.push(pref);
            save(payload);
        }
        return pref;
    },
    updateCreatorNotificationPreference(userId, creatorId, updates) {
        const payload = load();
        let pref = payload.creatorNotificationPreferences.find((item) => item.userId === userId && item.creatorId === creatorId);
        if (!pref) {
            pref = {
                userId,
                creatorId,
                upload: 'in_app',
                broadcast: 'in_app',
                muted: false,
                updatedAt: new Date().toISOString(),
            };
            payload.creatorNotificationPreferences.push(pref);
        }
        pref.upload = updates.upload ?? pref.upload;
        pref.broadcast = updates.broadcast ?? pref.broadcast;
        pref.muted = typeof updates.muted === 'boolean' ? updates.muted : pref.muted;
        pref.updatedAt = new Date().toISOString();
        save(payload);
        return pref;
    },
    listCreatorUploadAudience(creatorId) {
        const payload = load();
        return payload.creatorNotificationPreferences
            .filter((item) => item.creatorId === creatorId && !item.muted && item.upload !== 'off')
            .map((item) => ({ userId: item.userId, channel: item.upload }));
    },
    countFollowersForCreator(creatorId) {
        const payload = load();
        const followers = new Set();
        for (const pref of payload.creatorNotificationPreferences) {
            if (pref.creatorId !== creatorId)
                continue;
            if (pref.muted)
                continue;
            if (pref.upload === 'off' && pref.broadcast === 'off')
                continue;
            followers.add(pref.userId);
        }
        return followers.size;
    },
    countFollowingForUser(userId) {
        const payload = load();
        const creators = new Set();
        for (const pref of payload.creatorNotificationPreferences) {
            if (pref.userId !== userId)
                continue;
            if (pref.muted)
                continue;
            if (pref.upload === 'off' && pref.broadcast === 'off')
                continue;
            creators.add(pref.creatorId);
        }
        return creators.size;
    },
    listFollowersForCreator(creatorId) {
        const payload = load();
        const followers = new Set();
        for (const pref of payload.creatorNotificationPreferences) {
            if (pref.creatorId !== creatorId)
                continue;
            if (pref.muted)
                continue;
            if (pref.upload === 'off' && pref.broadcast === 'off')
                continue;
            followers.add(pref.userId);
        }
        return [...followers];
    },
    listFollowingForUser(userId) {
        const payload = load();
        const creators = new Set();
        for (const pref of payload.creatorNotificationPreferences) {
            if (pref.userId !== userId)
                continue;
            if (pref.muted)
                continue;
            if (pref.upload === 'off' && pref.broadcast === 'off')
                continue;
            creators.add(pref.creatorId);
        }
        return [...creators];
    },
    createNotification(input) {
        const payload = load();
        const settings = this.ensureNotificationsSettings(input.userId);
        const preferred = input.channel ?? settings.categories[input.type];
        if (preferred === 'off') {
            return {
                id: id('notif-suppressed'),
                userId: input.userId,
                type: input.type,
                title: input.title,
                body: input.body,
                data: input.data,
                createdAt: new Date().toISOString(),
                delivery: {
                    inApp: false,
                    pushEligible: false,
                    pushSuppressedByQuietHours: false,
                },
            };
        }
        const quietSuppressed = preferred === 'in_app_push' && isWithinQuietHours(settings);
        const created = {
            id: id('notif'),
            userId: input.userId,
            type: input.type,
            title: input.title,
            body: input.body,
            data: input.data,
            createdAt: new Date().toISOString(),
            delivery: {
                inApp: true,
                pushEligible: preferred === 'in_app_push',
                pushSuppressedByQuietHours: quietSuppressed,
            },
        };
        payload.notifications.unshift(created);
        updateNotificationCap(payload, input.userId);
        save(payload);
        return created;
    },
    listNotifications(userId, options) {
        const payload = load();
        const unreadCount = payload.notifications.filter((item) => item.userId === userId && !item.readAt).length;
        const limit = Math.max(1, Math.min(Number(options?.limit ?? 40), 100));
        const all = payload.notifications
            .filter((item) => item.userId === userId)
            .filter((item) => (options?.unreadOnly ? !item.readAt : true))
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        if (!options?.cursor) {
            const items = all.slice(0, limit);
            const nextCursor = all.length > limit ? all[limit - 1].id : null;
            return { items, nextCursor, unreadCount };
        }
        const idx = all.findIndex((item) => item.id === options.cursor);
        if (idx < 0) {
            const items = all.slice(0, limit);
            const nextCursor = all.length > limit ? all[limit - 1].id : null;
            return { items, nextCursor, unreadCount };
        }
        const start = idx + 1;
        const items = all.slice(start, start + limit);
        const nextCursor = all.length > start + limit ? all[start + limit - 1].id : null;
        return { items, nextCursor, unreadCount };
    },
    markNotificationRead(userId, notificationId) {
        const payload = load();
        const notification = payload.notifications.find((item) => item.id === notificationId && item.userId === userId);
        if (!notification)
            throw new errorHandler_1.HttpError(404, 'Notification not found');
        if (!notification.readAt) {
            notification.readAt = new Date().toISOString();
            save(payload);
        }
        return notification;
    },
    markAllNotificationsRead(userId) {
        const payload = load();
        let marked = 0;
        for (const item of payload.notifications) {
            if (item.userId === userId && !item.readAt) {
                item.readAt = new Date().toISOString();
                marked += 1;
            }
        }
        if (marked > 0)
            save(payload);
        return { marked };
    },
    blockUser(blockerId, blockedId) {
        if (blockerId === blockedId)
            throw new errorHandler_1.HttpError(400, 'You cannot block yourself');
        const payload = load();
        const existing = payload.blocks.find((item) => item.blockerId === blockerId && item.blockedId === blockedId);
        if (existing)
            return existing;
        const created = {
            blockerId,
            blockedId,
            createdAt: new Date().toISOString(),
        };
        payload.blocks.push(created);
        save(payload);
        return created;
    },
    unblockUser(blockerId, blockedId) {
        const payload = load();
        payload.blocks = payload.blocks.filter((item) => !(item.blockerId === blockerId && item.blockedId === blockedId));
        save(payload);
        return { ok: true };
    },
    listBlockedUsers(blockerId) {
        return load().blocks.filter((item) => item.blockerId === blockerId);
    },
    isBlockedEitherDirection(userA, userB) {
        const payload = load();
        return payload.blocks.some((item) => (item.blockerId === userA && item.blockedId === userB)
            || (item.blockerId === userB && item.blockedId === userA));
    },
    reportMessage(input) {
        const payload = load();
        const message = payload.messages.find((item) => item.id === input.messageId);
        if (!message)
            throw new errorHandler_1.HttpError(404, 'Message not found');
        const existing = payload.reports.find((item) => item.reporterId === input.reporterId && item.messageId === input.messageId);
        if (existing)
            return existing;
        const created = {
            id: id('msg-report'),
            reporterId: input.reporterId,
            reportedUserId: message.senderId,
            messageId: input.messageId,
            reason: input.reason.trim() || 'abuse',
            createdAt: new Date().toISOString(),
        };
        payload.reports.unshift(created);
        payload.reports = payload.reports.slice(0, MAX_REPORTS);
        save(payload);
        return created;
    },
};
//# sourceMappingURL=messagingStore.js.map