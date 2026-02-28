"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const auth_1 = require("../middleware/auth");
const errorHandler_1 = require("../middleware/errorHandler");
const config_1 = require("../config");
const adminStore_1 = require("../services/adminStore");
const userRepository_1 = require("../repositories/userRepository");
const messagingStore_1 = require("../services/messagingStore");
const router = (0, express_1.Router)();
const createConversationLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
});
const sendMessageLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
});
const sseClients = new Map();
function sendSse(userId, event, payload) {
    const clients = sseClients.get(userId);
    if (!clients || clients.size === 0)
        return;
    const serialized = JSON.stringify(payload);
    for (const res of clients) {
        res.write(`event: ${event}\n`);
        res.write(`data: ${serialized}\n\n`);
    }
}
async function assertUserExists(userId) {
    const user = await (0, userRepository_1.findUserById)(userId);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
}
function parseConversationType(value) {
    if (value === 'group')
        return 'group';
    if (value === 'broadcast')
        return 'broadcast';
    return 'dm';
}
router.get('/events', async (req, res) => {
    const authHeader = req.headers.authorization;
    const queryToken = typeof req.query.token === 'string' ? req.query.token : undefined;
    let userId = req.userId;
    if (!userId) {
        const token = queryToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : '');
        if (!token) {
            throw new errorHandler_1.HttpError(401, 'Missing authentication token for event stream');
        }
        try {
            const payload = jsonwebtoken_1.default.verify(token, config_1.config.jwt.secret);
            if (adminStore_1.adminStore.isUserBanned(payload.sub)) {
                throw new errorHandler_1.HttpError(403, 'Account is suspended');
            }
            userId = payload.sub;
        }
        catch {
            throw new errorHandler_1.HttpError(401, 'Invalid or expired token');
        }
    }
    if (!userId) {
        throw new errorHandler_1.HttpError(401, 'Unauthorized');
    }
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.write('event: connected\n');
    res.write(`data: ${JSON.stringify({ ok: true, ts: new Date().toISOString() })}\n\n`);
    let clients = sseClients.get(userId);
    if (!clients) {
        clients = new Set();
        sseClients.set(userId, clients);
    }
    clients.add(res);
    const heartbeat = setInterval(() => {
        res.write(`event: heartbeat\n`);
        res.write(`data: ${JSON.stringify({ ts: new Date().toISOString() })}\n\n`);
    }, 30000);
    req.on('close', () => {
        clearInterval(heartbeat);
        const next = sseClients.get(userId);
        if (!next)
            return;
        next.delete(res);
        if (next.size === 0)
            sseClients.delete(userId);
    });
});
router.get('/conversations', auth_1.requireAuth, async (req, res) => {
    const userId = req.userId;
    const items = messagingStore_1.messagingStore.listConversationsForUser(userId);
    res.json({ items });
});
router.post('/conversations', auth_1.requireAuth, createConversationLimiter, async (req, res) => {
    const creatorUserId = req.userId;
    const body = req.body;
    const type = parseConversationType(body.type);
    const participantIds = (body.participantIds ?? []).map((value) => String(value));
    for (const participantId of participantIds) {
        await assertUserExists(participantId);
        if (messagingStore_1.messagingStore.isBlockedEitherDirection(creatorUserId, participantId)) {
            throw new errorHandler_1.HttpError(403, 'Cannot create conversation due to block status.');
        }
    }
    const conversation = messagingStore_1.messagingStore.createConversation({
        type,
        creatorUserId,
        participantIds,
        title: body.title,
        allowReplies: body.allowReplies,
        typingIndicatorsEnabled: body.typingIndicatorsEnabled,
        readReceiptsEnabled: body.readReceiptsEnabled,
        collaboratorIds: body.collaboratorIds,
    });
    res.status(201).json({ conversation });
});
router.post('/conversations/:id/subscribe', auth_1.requireAuth, async (req, res) => {
    const conversation = messagingStore_1.messagingStore.subscribeToBroadcast(req.params.id, req.userId);
    res.json({ conversation });
});
router.delete('/conversations/:id/subscribe', auth_1.requireAuth, async (req, res) => {
    const conversation = messagingStore_1.messagingStore.unsubscribeFromBroadcast(req.params.id, req.userId);
    res.json({ conversation });
});
router.get('/conversations/:id/messages', auth_1.requireAuth, async (req, res) => {
    const cursor = typeof req.query.cursor === 'string' ? req.query.cursor : undefined;
    const limit = typeof req.query.limit === 'string' ? Number(req.query.limit) : undefined;
    const result = messagingStore_1.messagingStore.listMessages(req.params.id, req.userId, { cursor, limit });
    res.json(result);
});
router.post('/conversations/:id/messages/read', auth_1.requireAuth, async (req, res) => {
    const conversation = messagingStore_1.messagingStore.getConversationForUser(req.params.id, req.userId);
    const state = messagingStore_1.messagingStore.markConversationRead(req.params.id, req.userId);
    const recipients = new Set();
    if (conversation.type === 'broadcast') {
        conversation.subscriberIds.forEach((id) => recipients.add(id));
        conversation.collaboratorIds.forEach((id) => recipients.add(id));
        if (conversation.ownerUserId)
            recipients.add(conversation.ownerUserId);
    }
    else {
        conversation.participantIds.forEach((id) => recipients.add(id));
    }
    recipients.delete(req.userId);
    for (const recipientId of recipients) {
        sendSse(recipientId, 'conversation:read', {
            conversationId: req.params.id,
            userId: req.userId,
            state,
            ts: new Date().toISOString(),
        });
    }
    res.json({ state });
});
router.post('/conversations/:id/typing', auth_1.requireAuth, async (req, res) => {
    const body = req.body;
    const conversation = messagingStore_1.messagingStore.getConversationForUser(req.params.id, req.userId);
    if (!conversation.typingIndicatorsEnabled) {
        res.json({ ok: true, suppressed: true });
        return;
    }
    const recipients = messagingStore_1.messagingStore
        .listConversationRecipients(conversation.id)
        .filter((userId) => userId !== req.userId);
    for (const recipientId of recipients) {
        sendSse(recipientId, 'conversation:typing', {
            conversationId: conversation.id,
            userId: req.userId,
            isTyping: Boolean(body.isTyping),
            ts: new Date().toISOString(),
        });
    }
    res.json({ ok: true });
});
router.patch('/conversations/:id/settings', auth_1.requireAuth, async (req, res) => {
    const body = req.body;
    const state = messagingStore_1.messagingStore.updateConversationMemberSettings({
        conversationId: req.params.id,
        userId: req.userId,
        muted: body.muted,
        pinned: body.pinned,
        quietModeUntil: body.quietModeUntil,
    });
    res.json({ state });
});
router.post('/conversations/:id/messages', auth_1.requireAuth, sendMessageLimiter, async (req, res) => {
    const body = req.body;
    const conversation = messagingStore_1.messagingStore.getConversationForUser(req.params.id, req.userId);
    const recipientCandidates = conversation.type === 'broadcast'
        ? [...conversation.subscriberIds, ...conversation.collaboratorIds, conversation.ownerUserId].filter(Boolean)
        : conversation.participantIds;
    for (const participantId of recipientCandidates) {
        if (participantId === req.userId)
            continue;
        if (messagingStore_1.messagingStore.isBlockedEitherDirection(req.userId, participantId)) {
            throw new errorHandler_1.HttpError(403, 'Cannot send message due to block status.');
        }
    }
    const result = messagingStore_1.messagingStore.sendMessage({
        conversationId: req.params.id,
        senderId: req.userId,
        content: body.content ?? '',
        attachments: body.attachments,
        replyToMessageId: body.replyToMessageId,
    });
    for (const recipientId of result.recipientIds) {
        if (conversation.type === 'broadcast' && conversation.ownerUserId) {
            const pref = messagingStore_1.messagingStore.getCreatorNotificationPreference(recipientId, conversation.ownerUserId);
            if (pref.muted || pref.broadcast === 'off') {
                continue;
            }
        }
        const notification = messagingStore_1.messagingStore.createNotification({
            userId: recipientId,
            type: conversation.type === 'broadcast' ? 'broadcast_post' : 'dm',
            title: conversation.type === 'broadcast' ? `New post in ${conversation.title ?? 'broadcast channel'}` : 'New message',
            body: result.message.content.slice(0, 140) || 'Sent an attachment',
            data: {
                conversationId: conversation.id,
                messageId: result.message.id,
            },
            channel: conversation.type === 'broadcast' && conversation.ownerUserId
                ? messagingStore_1.messagingStore.getCreatorNotificationPreference(recipientId, conversation.ownerUserId).broadcast
                : undefined,
        });
        if (notification.delivery.inApp) {
            sendSse(recipientId, 'notification', notification);
        }
        sendSse(recipientId, 'message', { conversationId: conversation.id, message: result.message });
    }
    sendSse(req.userId, 'message:sent', { conversationId: conversation.id, message: result.message });
    res.status(201).json({ message: result.message, conversation: result.conversation });
});
router.post('/messages/:id/react', auth_1.requireAuth, async (req, res) => {
    const body = req.body;
    const message = messagingStore_1.messagingStore.reactToMessage({
        messageId: req.params.id,
        userId: req.userId,
        emoji: body.emoji ?? '',
    });
    res.json({ message });
});
router.post('/messages/:id/report', auth_1.requireAuth, async (req, res) => {
    const body = req.body;
    const report = messagingStore_1.messagingStore.reportMessage({
        reporterId: req.userId,
        messageId: req.params.id,
        reason: body.reason ?? 'abuse',
    });
    res.status(201).json({ report });
});
router.get('/notifications', auth_1.requireAuth, async (req, res) => {
    const cursor = typeof req.query.cursor === 'string' ? req.query.cursor : undefined;
    const limit = typeof req.query.limit === 'string' ? Number(req.query.limit) : undefined;
    const unreadOnly = req.query.unreadOnly === '1' || req.query.unreadOnly === 'true';
    const result = messagingStore_1.messagingStore.listNotifications(req.userId, { cursor, limit, unreadOnly });
    res.json(result);
});
router.post('/notifications/:id/read', auth_1.requireAuth, async (req, res) => {
    const notification = messagingStore_1.messagingStore.markNotificationRead(req.userId, req.params.id);
    res.json({ notification });
});
router.post('/notifications/read-all', auth_1.requireAuth, async (req, res) => {
    const result = messagingStore_1.messagingStore.markAllNotificationsRead(req.userId);
    res.json(result);
});
router.get('/notifications/settings', auth_1.requireAuth, async (req, res) => {
    const settings = messagingStore_1.messagingStore.getNotificationSettings(req.userId);
    res.json({ settings });
});
router.patch('/notifications/settings', auth_1.requireAuth, async (req, res) => {
    const body = req.body;
    const settings = messagingStore_1.messagingStore.updateNotificationSettings(req.userId, {
        categories: body.categories,
        quietHours: body.quietHours,
        experience: body.experience,
    });
    res.json({ settings });
});
router.get('/notifications/creators/:creatorId', auth_1.requireAuth, async (req, res) => {
    const pref = messagingStore_1.messagingStore.getCreatorNotificationPreference(req.userId, req.params.creatorId);
    res.json({ preference: pref });
});
router.patch('/notifications/creators/:creatorId', auth_1.requireAuth, async (req, res) => {
    const body = req.body;
    const preference = messagingStore_1.messagingStore.updateCreatorNotificationPreference(req.userId, req.params.creatorId, {
        upload: body.upload,
        broadcast: body.broadcast,
        muted: body.muted,
    });
    res.json({ preference });
});
router.get('/blocks', auth_1.requireAuth, async (req, res) => {
    const items = messagingStore_1.messagingStore.listBlockedUsers(req.userId);
    res.json({ items });
});
router.post('/blocks/:blockedUserId', auth_1.requireAuth, async (req, res) => {
    const blockedUserId = req.params.blockedUserId;
    await assertUserExists(blockedUserId);
    const block = messagingStore_1.messagingStore.blockUser(req.userId, blockedUserId);
    res.status(201).json({ block });
});
router.delete('/blocks/:blockedUserId', auth_1.requireAuth, async (req, res) => {
    const result = messagingStore_1.messagingStore.unblockUser(req.userId, req.params.blockedUserId);
    res.json(result);
});
exports.default = router;
//# sourceMappingURL=messaging.js.map