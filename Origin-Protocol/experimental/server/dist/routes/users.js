"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const zod_1 = require("zod");
const auth_1 = require("../middleware/auth");
const errorHandler_1 = require("../middleware/errorHandler");
const videoRepository_1 = require("../repositories/videoRepository");
const userRepository_1 = require("../repositories/userRepository");
const syncHistoryStore_1 = require("../services/syncHistoryStore");
const adminStore_1 = require("../services/adminStore");
const messagingStore_1 = require("../services/messagingStore");
const userSettingsStore_1 = require("../services/userSettingsStore");
const prisma_1 = require("../models/prisma");
const store_1 = require("../models/store");
const config_1 = require("../config");
const videoVerificationService_1 = require("../services/videoVerificationService");
const router = (0, express_1.Router)();
const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;
const updateSchema = zod_1.z.object({
    username: zod_1.z.string().trim().toLowerCase().regex(USERNAME_PATTERN).optional(),
    displayName: zod_1.z.string().max(64).optional(),
    bio: zod_1.z.string().max(280).optional(),
    avatarUrl: zod_1.z.union([
        zod_1.z.string().max(4096).refine((value) => /^https?:\/\//i.test(value), 'Avatar URL must be http(s) URL'),
        zod_1.z.string().max(600000).refine((value) => /^data:image\//i.test(value), 'Avatar data URL must be an image'),
        zod_1.z.null(),
    ]).optional(),
    creatorKeyId: zod_1.z.string().max(256).optional(),
});
const searchSchema = zod_1.z.object({
    query: zod_1.z.string().min(1).max(80),
    limit: zod_1.z.coerce.number().int().min(1).max(30).optional(),
});
const socialGraphSchema = zod_1.z.object({
    type: zod_1.z.union([zod_1.z.literal('followers'), zod_1.z.literal('following')]).default('followers'),
    limit: zod_1.z.coerce.number().int().min(1).max(100).default(24),
});
const changePasswordSchema = zod_1.z.object({
    currentPassword: zod_1.z.string().min(8),
    newPassword: zod_1.z.string().min(8),
});
const protectionSweepSchema = zod_1.z.object({
    includeAlreadyProtected: zod_1.z.boolean().optional(),
});
const updateSettingsSchema = zod_1.z.record(zod_1.z.any());
const revokeSessionSchema = zod_1.z.object({
    sessionId: zod_1.z.string().min(1),
});
const ORIGIN_VERIFY_MARKER = '[origin_verification]';
const ORIGIN_PROTECTION_MARKER = '[origin_protection]';
const ORIGIN_FINGERPRINT_MARKER = '[origin_fingerprint]';
function appendMarker(base, marker, payload) {
    if (base.includes(marker))
        return base;
    const encoded = `${marker}${JSON.stringify(payload)}`;
    const clean = base.trim();
    return clean ? `${clean}\n\n${encoded}` : encoded;
}
const syncHistoryCreateSchema = zod_1.z.object({
    status: zod_1.z.union([zod_1.z.literal('success'), zod_1.z.literal('failed')]),
    title: zod_1.z.string().max(200),
    videoUrl: zod_1.z.string().max(2048),
    videoId: zod_1.z.string().optional(),
    message: zod_1.z.string().max(500).optional(),
    payloadJson: zod_1.z.string().max(100000),
});
// GET /api/users/me/sync-history
router.get('/me/sync-history', auth_1.requireAuth, (req, res) => {
    const items = syncHistoryStore_1.syncHistoryStore.listByUser(req.userId);
    res.json({ items });
});
// POST /api/users/me/sync-history
router.post('/me/sync-history', auth_1.requireAuth, (req, res) => {
    const parsed = syncHistoryCreateSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const items = syncHistoryStore_1.syncHistoryStore.append({
        userId: req.userId,
        status: parsed.data.status,
        title: parsed.data.title,
        videoUrl: parsed.data.videoUrl,
        videoId: parsed.data.videoId,
        message: parsed.data.message,
        payloadJson: parsed.data.payloadJson,
    });
    res.status(201).json({ items });
});
// DELETE /api/users/me/sync-history
router.delete('/me/sync-history', auth_1.requireAuth, (req, res) => {
    syncHistoryStore_1.syncHistoryStore.clearByUser(req.userId);
    res.status(204).send();
});
// GET /api/users/me/payouts
router.get('/me/payouts', auth_1.requireAuth, (req, res) => {
    const latest = adminStore_1.adminStore.getLatestPayoutRun();
    if (!latest) {
        res.json({
            monthKey: null,
            creatorPool: 0,
            totalEligibleViews: 0,
            creatorEligibleViews: 0,
            creatorShare: 0,
            estimatedPayout: 0,
            finalPayout: 0,
            payoutsActive: false,
            reason: 'No payout run has been computed yet.',
        });
        return;
    }
    const row = latest.creators.find((item) => item.creatorId === req.userId) ?? {
        creatorId: req.userId,
        eligibleViews: 0,
        estimatedPayout: 0,
    };
    const totalEligible = latest.computed.totalEligibleViews;
    const share = totalEligible > 0 ? row.eligibleViews / totalEligible : 0;
    res.json({
        monthKey: latest.monthKey,
        creatorPool: latest.computed.creatorPoolBeforeDistribution,
        totalEligibleViews: totalEligible,
        creatorEligibleViews: row.eligibleViews,
        creatorShare: share,
        estimatedPayout: row.estimatedPayout,
        finalPayout: row.estimatedPayout,
        payoutsActive: latest.computed.activation.payoutsActive,
        reason: latest.computed.activation.reason,
    });
});
// GET /api/users/search?query=...&limit=12
router.get('/search', auth_1.requireAuth, async (req, res) => {
    const parsed = searchSchema.safeParse({
        query: req.query.query,
        limit: req.query.limit,
    });
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const users = await (0, userRepository_1.searchUsers)(parsed.data.query, parsed.data.limit ?? 12);
    const items = users
        .filter((user) => user.id !== req.userId)
        .map((user) => {
        const { email: _email, ...publicUser } = (0, userRepository_1.toPublicUser)(user);
        return publicUser;
    });
    res.json({ items });
});
// GET /api/users/by-username/:username
router.get('/by-username/:username', async (req, res) => {
    const normalized = req.params.username.trim().toLowerCase();
    if (!USERNAME_PATTERN.test(normalized)) {
        res.status(400).json({ error: 'Invalid username format.' });
        return;
    }
    const user = await (0, userRepository_1.findUserByUsername)(normalized);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const { email: _email, ...publicUser } = (0, userRepository_1.toPublicUser)(user);
    res.json({ user: publicUser });
});
// GET /api/users/:id
router.get('/:id', async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.params.id);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const { email: _email, ...publicUser } = (0, userRepository_1.toPublicUser)(user);
    res.json({ user: publicUser });
});
// GET /api/users/:id/videos
router.get('/:id/videos', async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.params.id);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const videos = await (0, videoRepository_1.listVideosByCreator)(req.params.id);
    res.json({ items: videos });
});
// GET /api/users/:id/profile-stats
router.get('/:id/profile-stats', async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.params.id);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const videos = await (0, videoRepository_1.listVideosByCreator)(req.params.id);
    const totalViews = videos.reduce((sum, video) => sum + (video.viewCount || 0), 0);
    const totalLikes = videos.reduce((sum, video) => sum + (video.likeCount || 0), 0);
    const totalVerified = videos.filter((video) => Boolean(video.originVerified)).length;
    const totalProtected = videos.filter((video) => Boolean(video.originBundleId)).length;
    res.json({
        stats: {
            followersCount: messagingStore_1.messagingStore.countFollowersForCreator(user.id),
            followingCount: messagingStore_1.messagingStore.countFollowingForUser(user.id),
            totalVideos: videos.length,
            totalViews,
            totalLikes,
            totalVerified,
            totalProtected,
        },
    });
});
// GET /api/users/:id/social-graph?type=followers|following&limit=24
router.get('/:id/social-graph', async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.params.id);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const parsed = socialGraphSchema.safeParse({
        type: req.query.type,
        limit: req.query.limit,
    });
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const sourceIds = parsed.data.type === 'followers'
        ? messagingStore_1.messagingStore.listFollowersForCreator(user.id)
        : messagingStore_1.messagingStore.listFollowingForUser(user.id);
    const ids = sourceIds.slice(0, parsed.data.limit);
    const loaded = await Promise.all(ids.map((id) => (0, userRepository_1.findUserById)(id)));
    const items = loaded
        .filter((item) => Boolean(item))
        .map((item) => {
        const { email: _email, ...publicUser } = (0, userRepository_1.toPublicUser)(item);
        return publicUser;
    });
    res.json({
        type: parsed.data.type,
        total: sourceIds.length,
        items,
    });
});
// PATCH /api/users/me
router.patch('/me', auth_1.requireAuth, async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.userId);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const parsed = updateSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    if (parsed.data.username && parsed.data.username !== user.username) {
        const existing = await (0, userRepository_1.findUserByUsername)(parsed.data.username);
        if (existing && existing.id !== user.id) {
            res.status(409).json({ error: 'Username is already taken.' });
            return;
        }
    }
    const updated = await (0, userRepository_1.updateUser)(user.id, parsed.data);
    if (!updated)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const { email: _email, ...publicUser } = (0, userRepository_1.toPublicUser)(updated);
    res.json({ user: publicUser });
});
// PATCH /api/users/me/password
router.patch('/me/password', auth_1.requireAuth, async (req, res) => {
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const user = await (0, userRepository_1.findUserById)(req.userId);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const ok = await bcryptjs_1.default.compare(parsed.data.currentPassword, user.passwordHash);
    if (!ok) {
        res.status(400).json({ error: 'Current password is incorrect' });
        return;
    }
    if (parsed.data.currentPassword === parsed.data.newPassword) {
        res.status(400).json({ error: 'New password must be different' });
        return;
    }
    const newPasswordHash = await bcryptjs_1.default.hash(parsed.data.newPassword, 10);
    await (0, userRepository_1.updateUserPassword)(user.id, newPasswordHash);
    res.json({ ok: true });
});
// GET /api/users/me/settings
router.get('/me/settings', auth_1.requireAuth, async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.userId);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const settings = userSettingsStore_1.userSettingsStore.get(user);
    res.json({ settings });
});
// PATCH /api/users/me/settings
router.patch('/me/settings', auth_1.requireAuth, async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.userId);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const parsed = updateSettingsSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const patch = parsed.data;
    const personal = patch.personalInformation;
    if (personal) {
        const updatePayload = {};
        if (typeof personal.username === 'string') {
            const normalized = personal.username.trim().toLowerCase();
            if (!USERNAME_PATTERN.test(normalized)) {
                res.status(400).json({ error: 'Invalid username format.' });
                return;
            }
            if (normalized !== user.username) {
                const existing = await (0, userRepository_1.findUserByUsername)(normalized);
                if (existing && existing.id !== user.id) {
                    res.status(409).json({ error: 'Username is already taken.' });
                    return;
                }
            }
            updatePayload.username = normalized;
        }
        if (typeof personal.displayName === 'string') {
            updatePayload.displayName = personal.displayName.slice(0, 64);
        }
        if (typeof personal.bio === 'string') {
            updatePayload.bio = personal.bio.slice(0, 280);
        }
        if (typeof personal.profilePhoto === 'string') {
            const value = personal.profilePhoto.trim();
            if (value && !/^https?:\/\//i.test(value) && !/^data:image\//i.test(value)) {
                res.status(400).json({ error: 'Profile photo must be an http(s) URL or data:image URL.' });
                return;
            }
            updatePayload.avatarUrl = value || null;
        }
        if (Object.keys(updatePayload).length > 0) {
            const updated = await (0, userRepository_1.updateUser)(user.id, updatePayload);
            if (updated) {
                Object.assign(user, updated);
            }
        }
    }
    const settings = userSettingsStore_1.userSettingsStore.update(user, patch);
    res.json({ settings });
});
// POST /api/users/me/settings/revoke-session
router.post('/me/settings/revoke-session', auth_1.requireAuth, async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.userId);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const parsed = revokeSessionSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const settings = userSettingsStore_1.userSettingsStore.revokeSession(user, parsed.data.sessionId);
    res.json({ settings });
});
// GET /api/users/me/settings/export
router.get('/me/settings/export', auth_1.requireAuth, async (req, res) => {
    const user = await (0, userRepository_1.findUserById)(req.userId);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    const payload = userSettingsStore_1.userSettingsStore.export(user);
    res.json(payload);
});
// DELETE /api/users/me/settings
router.delete('/me/settings', auth_1.requireAuth, async (req, res) => {
    userSettingsStore_1.userSettingsStore.delete(req.userId);
    res.status(204).send();
});
// POST /api/users/me/videos/protection-sweep
router.post('/me/videos/protection-sweep', auth_1.requireAuth, async (req, res) => {
    const parsed = protectionSweepSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const user = await (0, userRepository_1.findUserById)(req.userId);
    if (!user)
        throw new errorHandler_1.HttpError(404, 'User not found');
    if (!user.creatorKeyId) {
        res.status(403).json({ error: 'Creator membership is required before running a protection sweep.' });
        return;
    }
    const includeAlreadyProtected = Boolean(parsed.data.includeAlreadyProtected);
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const videos = await prisma_1.prisma.video.findMany({
            where: { creatorId: user.id },
            select: {
                id: true,
                creatorId: true,
                title: true,
                description: true,
                videoUrl: true,
                originBundleId: true,
                originVerified: true,
            },
        });
        let updatedCount = 0;
        for (const video of videos) {
            const hasProtection = Boolean(video.originBundleId) || Boolean(video.description?.includes(ORIGIN_PROTECTION_MARKER));
            if (!includeAlreadyProtected && hasProtection)
                continue;
            const bundleId = video.originBundleId || `${user.id.slice(0, 8)}.${video.id.slice(0, 8)}.origin.zip`;
            const contentHash = (0, videoVerificationService_1.buildSyntheticFingerprint)(video.id, video.videoUrl);
            let nextDescription = video.description ?? '';
            nextDescription = appendMarker(nextDescription, ORIGIN_PROTECTION_MARKER, {
                protected: true,
                options: ['creator-id', 'asset-id', 'platform-targets', 'key-id', 'origin-logo'],
                platforms: ['Meta', 'Instagram', 'TikTok'],
            });
            nextDescription = appendMarker(nextDescription, ORIGIN_FINGERPRINT_MARKER, {
                algorithm: 'sha256',
                contentHash,
                ownerCreatorId: user.id,
                stampedAt: new Date().toISOString(),
            });
            const verification = await (0, videoVerificationService_1.verifyCreatorUploadAuthenticity)({
                creatorId: user.id,
                keyId: user.creatorKeyId,
                assetId: bundleId,
                contentHash,
                allowKeyFallback: true,
                sourceLabel: 'protection sweep',
            });
            nextDescription = verification.verifyResult
                ? (0, videoVerificationService_1.appendOriginVerificationMetadata)(nextDescription, verification.verifyResult)
                : appendMarker(nextDescription, ORIGIN_VERIFY_MARKER, {
                    checkedAt: new Date().toISOString(),
                    reasons: [
                        {
                            code: 'sweep_pending_verification',
                            severity: 'warning',
                            message: 'Protection sweep completed but verification reasons are unavailable.',
                            platformAction: 'keep_unverified',
                            creatorAction: 'Retry verification from admin dashboard.',
                        },
                    ],
                });
            await prisma_1.prisma.video.update({
                where: { id: video.id },
                data: {
                    originBundleId: bundleId,
                    originVerified: verification.originVerified,
                    description: nextDescription,
                },
            });
            updatedCount += 1;
        }
        res.json({ updated: updatedCount, total: videos.length });
        return;
    }
    const myVideos = [...store_1.db.videos.values()].filter((item) => item.creatorId === user.id);
    let updatedCount = 0;
    for (const video of myVideos) {
        const hasProtection = Boolean(video.originBundleId) || Boolean(video.description?.includes(ORIGIN_PROTECTION_MARKER));
        if (!includeAlreadyProtected && hasProtection)
            continue;
        const bundleId = video.originBundleId || `${user.id.slice(0, 8)}.${video.id.slice(0, 8)}.origin.zip`;
        const contentHash = (0, videoVerificationService_1.buildSyntheticFingerprint)(video.id, video.videoUrl);
        let nextDescription = video.description ?? '';
        nextDescription = appendMarker(nextDescription, ORIGIN_PROTECTION_MARKER, {
            protected: true,
            options: ['creator-id', 'asset-id', 'platform-targets', 'key-id', 'origin-logo'],
            platforms: ['Meta', 'Instagram', 'TikTok'],
        });
        nextDescription = appendMarker(nextDescription, ORIGIN_FINGERPRINT_MARKER, {
            algorithm: 'sha256',
            contentHash,
            ownerCreatorId: user.id,
            stampedAt: new Date().toISOString(),
        });
        const verification = await (0, videoVerificationService_1.verifyCreatorUploadAuthenticity)({
            creatorId: user.id,
            keyId: user.creatorKeyId,
            assetId: bundleId,
            contentHash,
            allowKeyFallback: true,
            sourceLabel: 'protection sweep',
        });
        nextDescription = verification.verifyResult
            ? (0, videoVerificationService_1.appendOriginVerificationMetadata)(nextDescription, verification.verifyResult)
            : appendMarker(nextDescription, ORIGIN_VERIFY_MARKER, {
                checkedAt: new Date().toISOString(),
                reasons: [
                    {
                        code: 'sweep_pending_verification',
                        severity: 'warning',
                        message: 'Protection sweep completed but verification reasons are unavailable.',
                        platformAction: 'keep_unverified',
                        creatorAction: 'Retry verification from admin dashboard.',
                    },
                ],
            });
        store_1.db.videos.set(video.id, {
            ...video,
            originBundleId: bundleId,
            originVerified: verification.originVerified,
            description: nextDescription,
        });
        updatedCount += 1;
    }
    res.json({ updated: updatedCount, total: myVideos.length });
});
exports.default = router;
//# sourceMappingURL=users.js.map