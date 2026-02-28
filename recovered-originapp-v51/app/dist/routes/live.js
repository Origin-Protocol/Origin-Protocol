"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const auth_1 = require("../middleware/auth");
const errorHandler_1 = require("../middleware/errorHandler");
const config_1 = require("../config");
const videoRepository_1 = require("../repositories/videoRepository");
const userRepository_1 = require("../repositories/userRepository");
const adminStore_1 = require("../services/adminStore");
const messagingStore_1 = require("../services/messagingStore");
const liveStore_1 = require("../services/liveStore");
const router = (0, express_1.Router)();
const LIVE_REQUIREMENTS = {
    minFollowers: 100,
    minTotalViews: 2500,
    minPublishedVideos: 5,
    minVerifiedVideos: 3,
};
const createSessionSchema = zod_1.z.object({
    title: zod_1.z.string().min(3).max(140),
    description: zod_1.z.string().max(500).optional(),
});
const updateSessionSchema = zod_1.z.object({
    action: zod_1.z.union([zod_1.z.literal('end'), zod_1.z.literal('join'), zod_1.z.literal('leave')]),
});
const postCommentSchema = zod_1.z.object({
    text: zod_1.z.string().min(1).max(500),
    parentId: zod_1.z.string().optional(),
});
const listSessionSchema = zod_1.z.object({
    status: zod_1.z.union([zod_1.z.literal('live'), zod_1.z.literal('ended'), zod_1.z.literal('all')]).default('live'),
    limit: zod_1.z.coerce.number().int().min(1).max(200).default(60),
});
async function isAdminLiveBypass(userId) {
    const user = await (0, userRepository_1.findUserById)(userId);
    if (!user)
        return false;
    const normalizedEmail = user.email.trim().toLowerCase();
    const isAdminEmail = config_1.config.membership.adminEmails.includes(normalizedEmail);
    return isAdminEmail || adminStore_1.adminStore.isPromotedAdmin(user.id);
}
async function computeEligibility(userId) {
    const videos = await (0, videoRepository_1.listVideosByCreator)(userId);
    const followers = messagingStore_1.messagingStore.countFollowersForCreator(userId);
    const totalViews = videos.reduce((sum, video) => sum + (video.viewCount || 0), 0);
    const verifiedVideos = videos.filter((video) => video.originVerified).length;
    const isAdminBypass = await isAdminLiveBypass(userId);
    const metrics = {
        followers,
        totalViews,
        publishedVideos: videos.length,
        verifiedVideos,
    };
    const unmet = [];
    if (!isAdminBypass) {
        if (metrics.followers < LIVE_REQUIREMENTS.minFollowers)
            unmet.push('followers');
        if (metrics.totalViews < LIVE_REQUIREMENTS.minTotalViews)
            unmet.push('totalViews');
        if (metrics.publishedVideos < LIVE_REQUIREMENTS.minPublishedVideos)
            unmet.push('publishedVideos');
        if (metrics.verifiedVideos < LIVE_REQUIREMENTS.minVerifiedVideos)
            unmet.push('verifiedVideos');
    }
    return {
        eligible: isAdminBypass || unmet.length === 0,
        isAdminBypass,
        metrics,
        requirements: LIVE_REQUIREMENTS,
        unmet,
    };
}
async function toSessionDto(sessionId, viewerUserId) {
    const session = liveStore_1.liveStore.getSession(sessionId);
    if (!session)
        return null;
    const host = await (0, userRepository_1.findUserById)(session.hostUserId);
    const comments = liveStore_1.liveStore.listComments(session.id);
    return {
        id: session.id,
        hostUserId: session.hostUserId,
        hostDisplayName: host?.displayName ?? 'Creator',
        hostUsername: host?.username ?? 'creator',
        title: session.title,
        description: session.description,
        status: session.status,
        startedAt: session.startedAt,
        endedAt: session.endedAt,
        viewerCount: session.viewerIds.length,
        peakViewerCount: session.peakViewerCount,
        likeCount: liveStore_1.liveStore.countSessionLikes(session.id),
        likedByMe: viewerUserId ? liveStore_1.liveStore.hasUserLikedSession(session.id, viewerUserId) : false,
        commentCount: comments.length,
    };
}
async function buildThreadedComments(sessionId, viewerUserId) {
    const rows = liveStore_1.liveStore.listComments(sessionId);
    const users = await Promise.all(rows.map((item) => (0, userRepository_1.findUserById)(item.authorId)));
    const userMap = new Map(rows.map((row, idx) => [row.authorId, users[idx]]));
    const nodes = new Map();
    rows.forEach((row) => {
        const author = userMap.get(row.authorId);
        nodes.set(row.id, {
            id: row.id,
            sessionId: row.sessionId,
            authorId: row.authorId,
            authorDisplayName: author?.displayName ?? 'User',
            authorUsername: author?.username ?? 'user',
            text: row.text,
            createdAt: row.createdAt,
            parentId: row.parentId,
            likeCount: liveStore_1.liveStore.countCommentLikes(row.id),
            likedByMe: viewerUserId ? liveStore_1.liveStore.hasUserLikedComment(row.id, viewerUserId) : false,
            replies: [],
        });
    });
    const roots = [];
    nodes.forEach((node) => {
        if (!node.parentId) {
            roots.push(node);
            return;
        }
        const parent = nodes.get(node.parentId);
        if (!parent) {
            roots.push(node);
            return;
        }
        parent.replies.push(node);
    });
    const sorter = (a, b) => a.createdAt.localeCompare(b.createdAt);
    roots.sort(sorter);
    roots.forEach((item) => item.replies.sort(sorter));
    return roots;
}
router.get('/eligibility', auth_1.requireAuth, async (req, res) => {
    const summary = await computeEligibility(req.userId);
    const activeSession = liveStore_1.liveStore.findLiveSessionByHost(req.userId);
    const active = activeSession ? await toSessionDto(activeSession.id, req.userId) : null;
    res.json({ ...summary, activeSession: active });
});
router.get('/sessions', auth_1.requireAuth, async (req, res) => {
    const parsed = listSessionSchema.safeParse(req.query);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const rows = liveStore_1.liveStore.listSessions(parsed.data.status, parsed.data.limit);
    const items = await Promise.all(rows.map((row) => toSessionDto(row.id, req.userId)));
    res.json({ items: items.filter((item) => Boolean(item)) });
});
router.post('/sessions', auth_1.requireAuth, async (req, res) => {
    const parsed = createSessionSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const existing = liveStore_1.liveStore.findLiveSessionByHost(req.userId);
    if (existing) {
        const dto = await toSessionDto(existing.id, req.userId);
        res.status(409).json({ error: 'You already have an active live session.', session: dto });
        return;
    }
    const eligibility = await computeEligibility(req.userId);
    if (!eligibility.eligible) {
        res.status(403).json({
            error: 'Live access is locked until your creator metrics meet minimum thresholds.',
            eligibility,
        });
        return;
    }
    const created = liveStore_1.liveStore.createSession({
        hostUserId: req.userId,
        title: parsed.data.title.trim(),
        description: parsed.data.description,
    });
    const dto = await toSessionDto(created.id, req.userId);
    res.status(201).json({ session: dto });
});
router.get('/sessions/:id', auth_1.requireAuth, async (req, res) => {
    const dto = await toSessionDto(req.params.id, req.userId);
    if (!dto) {
        throw new errorHandler_1.HttpError(404, 'Live session not found');
    }
    res.json({ session: dto });
});
router.post('/sessions/:id/action', auth_1.requireAuth, async (req, res) => {
    const parsed = updateSessionSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const session = liveStore_1.liveStore.getSession(req.params.id);
    if (!session)
        throw new errorHandler_1.HttpError(404, 'Live session not found');
    if (parsed.data.action === 'end') {
        if (session.hostUserId !== req.userId) {
            throw new errorHandler_1.HttpError(403, 'Only the host can end this live session');
        }
        const ended = liveStore_1.liveStore.endSession(session.id);
        const dto = ended ? await toSessionDto(ended.id, req.userId) : null;
        res.json({ session: dto });
        return;
    }
    const active = parsed.data.action === 'join';
    const updated = liveStore_1.liveStore.setViewerPresence(session.id, req.userId, active);
    const dto = updated ? await toSessionDto(updated.id, req.userId) : null;
    res.json({ session: dto });
});
router.post('/sessions/:id/like', auth_1.requireAuth, async (req, res) => {
    const session = liveStore_1.liveStore.getSession(req.params.id);
    if (!session)
        throw new errorHandler_1.HttpError(404, 'Live session not found');
    const liked = liveStore_1.liveStore.toggleSessionLike(session.id, req.userId);
    res.json({ liked, likeCount: liveStore_1.liveStore.countSessionLikes(session.id) });
});
router.get('/sessions/:id/comments', auth_1.requireAuth, async (req, res) => {
    const session = liveStore_1.liveStore.getSession(req.params.id);
    if (!session)
        throw new errorHandler_1.HttpError(404, 'Live session not found');
    const comments = await buildThreadedComments(session.id, req.userId);
    res.json({ comments });
});
router.post('/sessions/:id/comments', auth_1.requireAuth, async (req, res) => {
    const session = liveStore_1.liveStore.getSession(req.params.id);
    if (!session)
        throw new errorHandler_1.HttpError(404, 'Live session not found');
    if (session.status !== 'live') {
        throw new errorHandler_1.HttpError(400, 'Cannot post comments to an ended live session');
    }
    const parsed = postCommentSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const text = parsed.data.text.trim();
    if (!text) {
        res.status(400).json({ error: 'Comment text is required' });
        return;
    }
    let parentId;
    if (parsed.data.parentId) {
        const parent = liveStore_1.liveStore.getComment(parsed.data.parentId);
        if (!parent || parent.sessionId !== session.id) {
            throw new errorHandler_1.HttpError(400, 'Reply target is invalid');
        }
        parentId = parent.id;
    }
    const created = liveStore_1.liveStore.createComment({
        sessionId: session.id,
        authorId: req.userId,
        text,
        parentId,
    });
    const author = await (0, userRepository_1.findUserById)(req.userId);
    res.status(201).json({
        comment: {
            ...created,
            authorDisplayName: author?.displayName ?? 'User',
            authorUsername: author?.username ?? 'user',
            likeCount: 0,
            likedByMe: false,
            replies: [],
        },
    });
});
router.post('/comments/:id/like', auth_1.requireAuth, async (req, res) => {
    const comment = liveStore_1.liveStore.getComment(req.params.id);
    if (!comment)
        throw new errorHandler_1.HttpError(404, 'Live comment not found');
    const liked = liveStore_1.liveStore.toggleCommentLike(comment.id, req.userId);
    res.json({ liked, likeCount: liveStore_1.liveStore.countCommentLikes(comment.id) });
});
exports.default = router;
//# sourceMappingURL=live.js.map