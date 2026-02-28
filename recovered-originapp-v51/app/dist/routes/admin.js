"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const crypto_1 = __importDefault(require("crypto"));
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const multer_1 = __importDefault(require("multer"));
const zod_1 = require("zod");
const config_1 = require("../config");
const auth_1 = require("../middleware/auth");
const store_1 = require("../models/store");
const prisma_1 = require("../models/prisma");
const userRepository_1 = require("../repositories/userRepository");
const videoRepository_1 = require("../repositories/videoRepository");
const userRepository_2 = require("../repositories/userRepository");
const adminStore_1 = require("../services/adminStore");
const syncHistoryStore_1 = require("../services/syncHistoryStore");
const videoVerificationService_1 = require("../services/videoVerificationService");
const router = (0, express_1.Router)();
const toolUpload = (0, multer_1.default)({ storage: multer_1.default.memoryStorage() });
function isAdminBypassEmail(email) {
    const normalized = email.trim().toLowerCase();
    return config_1.config.membership.adminEmails.includes(normalized);
}
function isUserAdmin(user) {
    return isAdminBypassEmail(user.email) || adminStore_1.adminStore.isPromotedAdmin(user.id);
}
async function requireAdmin(req, res) {
    const user = await (0, userRepository_1.findUserById)(req.userId);
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return null;
    }
    if (!isUserAdmin(user)) {
        res.status(403).json({ error: 'Admin access required' });
        return null;
    }
    return { id: user.id, email: user.email };
}
const createToolVersionSchema = zod_1.z.object({
    version: zod_1.z.string().min(1).max(64),
    notes: zod_1.z.string().max(2000).optional(),
    fileName: zod_1.z.string().max(255).optional(),
    isLatest: zod_1.z.boolean().optional(),
    forceUpdate: zod_1.z.boolean().optional(),
});
const updateToolVersionSchema = zod_1.z.object({
    isLatest: zod_1.z.boolean().optional(),
    forceUpdate: zod_1.z.boolean().optional(),
});
const creatorAccessSchema = zod_1.z.object({
    active: zod_1.z.boolean(),
});
const adminRoleSchema = zod_1.z.object({
    active: zod_1.z.boolean(),
});
const banSchema = zod_1.z.object({
    banned: zod_1.z.boolean(),
});
const resolveReportSchema = zod_1.z.object({
    action: zod_1.z.literal('resolve'),
});
const reverifyVideoSchema = zod_1.z.object({
    force: zod_1.z.boolean().optional(),
});
const reverifyFailedSchema = zod_1.z.object({
    limit: zod_1.z.coerce.number().int().min(1).max(500).optional(),
    includeVerified: zod_1.z.boolean().optional(),
});
const verifyNowSchema = zod_1.z.object({
    force: zod_1.z.boolean().optional(),
    allowKeyFallback: zod_1.z.boolean().optional(),
    allowAdminOverrideOnFailure: zod_1.z.boolean().optional(),
});
const verifyBulkSchema = zod_1.z.object({
    limit: zod_1.z.coerce.number().int().min(1).max(2000).optional(),
    unverifiedOnly: zod_1.z.boolean().optional(),
    creatorId: zod_1.z.string().min(1).max(128).optional(),
    startDate: zod_1.z.string().datetime().optional(),
    endDate: zod_1.z.string().datetime().optional(),
    allowKeyFallback: zod_1.z.boolean().optional(),
    allowAdminOverrideOnFailure: zod_1.z.boolean().optional(),
    videoIds: zod_1.z.array(zod_1.z.string().min(1)).max(500).optional(),
});
const recheckRevocationsSchema = zod_1.z.object({
    limit: zod_1.z.coerce.number().int().min(1).max(2000).optional(),
    creatorId: zod_1.z.string().min(1).max(128).optional(),
    startDate: zod_1.z.string().datetime().optional(),
    endDate: zod_1.z.string().datetime().optional(),
    onlyVerified: zod_1.z.boolean().optional(),
    videoIds: zod_1.z.array(zod_1.z.string().min(1)).max(500).optional(),
});
const payoutConfigUpdateSchema = zod_1.z.object({
    enabled: zod_1.z.boolean().optional(),
    thresholds: zod_1.z.object({
        minMonthlyNetProfit: zod_1.z.number().nonnegative().optional(),
        minMonthlyRevenue: zod_1.z.number().nonnegative().optional(),
        minActiveMonthlyUsers: zod_1.z.number().nonnegative().optional(),
        minActiveCreators: zod_1.z.number().nonnegative().optional(),
        minMonthlyApiVerifications: zod_1.z.number().nonnegative().optional(),
    }).optional(),
    percentages: zod_1.z.object({
        subscriptionRevenuePct: zod_1.z.number().min(0).max(1).optional(),
        apiUsageRevenuePct: zod_1.z.number().min(0).max(1).optional(),
        boostRevenuePct: zod_1.z.number().min(0).max(1).optional(),
        monthlyProfitPct: zod_1.z.number().min(0).max(1).optional(),
    }).optional(),
});
const payoutRunSchema = zod_1.z.object({
    monthKey: zod_1.z.string().min(4).max(24),
    totalRevenue: zod_1.z.number().nonnegative(),
    infrastructureCost: zod_1.z.number().nonnegative().default(0),
    operatingCost: zod_1.z.number().nonnegative().default(0),
    subscriptionRevenue: zod_1.z.number().nonnegative().default(0),
    apiUsageRevenue: zod_1.z.number().nonnegative().default(0),
    boostRevenue: zod_1.z.number().nonnegative().default(0),
    activeMonthlyUsers: zod_1.z.number().nonnegative().default(0),
    activeCreators: zod_1.z.number().nonnegative().default(0),
    monthlyApiVerifications: zod_1.z.number().nonnegative().default(0),
});
const payoutFlagSchema = zod_1.z.object({
    reason: zod_1.z.string().min(3).max(500),
    status: zod_1.z.union([zod_1.z.literal('open'), zod_1.z.literal('reviewed'), zod_1.z.literal('cleared')]).optional(),
});
const recommendationConfigUpdateSchema = zod_1.z.object({
    weights: zod_1.z.object({
        interest: zod_1.z.number().min(0).max(1).optional(),
        community: zod_1.z.number().min(0).max(1).optional(),
        provenance: zod_1.z.number().min(0).max(1).optional(),
        health: zod_1.z.number().min(0).max(1).optional(),
        equity: zod_1.z.number().min(0).max(1).optional(),
    }).optional(),
    fairnessRotationFrequency: zod_1.z.number().int().min(1).max(20).optional(),
    creatorDominanceCap: zod_1.z.number().int().min(1).max(10).optional(),
    spotlightBoostVisibility: zod_1.z.number().min(0).max(10).optional(),
    healthDownrankThreshold: zod_1.z.number().min(-1).max(1).optional(),
    aiAdaptiveEnabled: zod_1.z.boolean().optional(),
});
function buildCreatorKeyId(userId) {
    return `origin-key-${userId.slice(0, 8)}-${Date.now().toString(36)}`;
}
async function loadAdminUsers(limit = 500) {
    const users = config_1.config.database.usePrisma && prisma_1.prisma
        ? (await prisma_1.prisma.user.findMany({
            orderBy: { createdAt: 'desc' },
            take: limit,
            select: {
                id: true,
                username: true,
                email: true,
                displayName: true,
                creatorKeyId: true,
                createdAt: true,
            },
        })).map((user) => ({
            ...user,
            createdAt: user.createdAt.toISOString(),
        }))
        : [...store_1.db.users.values()]
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
            .slice(0, limit)
            .map((user) => ({
            id: user.id,
            username: user.username,
            email: user.email,
            displayName: user.displayName,
            creatorKeyId: user.creatorKeyId,
            createdAt: user.createdAt,
        }));
    const bannedSet = new Set(adminStore_1.adminStore.listBannedUserIds());
    const promotedSet = new Set(adminStore_1.adminStore.listPromotedAdminUserIds());
    return users.map((user) => ({
        ...user,
        isAdmin: isAdminBypassEmail(user.email) || promotedSet.has(user.id),
        banned: bannedSet.has(user.id),
    }));
}
function computeVerification(videos) {
    return {
        sealed: videos.filter((video) => Boolean(video.originBundleId)).length,
        unsealed: videos.filter((video) => !video.originBundleId).length,
        verified: videos.filter((video) => video.originVerified).length,
        failed: videos.filter((video) => video.originBundleId && !video.originVerified).length,
        pending: videos.filter((video) => video.originBundleId && !video.originVerified && (video.originReasons?.length ?? 0) === 0).length,
        revokedOrInvalid: videos.filter((video) => !video.originVerified && (0, videoVerificationService_1.hasRevocationOrConflictReasons)(video.originReasons)).length,
    };
}
function buildCreatorSubscriptionRows(users) {
    return users.map((user) => ({
        userId: user.id,
        email: user.email,
        displayName: user.displayName,
        creatorAccess: Boolean(user.creatorKeyId),
        creatorKeyId: user.creatorKeyId,
        banned: Boolean(user.banned),
        status: user.creatorKeyId ? 'active' : 'inactive',
    }));
}
async function buildOverviewPayload() {
    const usersWithBan = await loadAdminUsers(500);
    const feed = await (0, videoRepository_1.listFeed)(1, 500);
    const videos = feed.items;
    const reports = adminStore_1.adminStore.listReports('all', 500);
    const bundleRows = videos
        .filter((video) => Boolean(video.originBundleId))
        .map((video) => ({
        id: video.id,
        title: video.title,
        creatorId: video.creatorId,
        originBundleId: video.originBundleId,
        originVerified: video.originVerified,
        createdAt: video.createdAt,
    }));
    const verification = computeVerification(videos);
    const creatorSubscriptionRows = buildCreatorSubscriptionRows(usersWithBan);
    const usageEvents = adminStore_1.adminStore.listUsageEvents(1000);
    const toolVersions = adminStore_1.adminStore.listToolVersions();
    const storedErrors = adminStore_1.adminStore.listErrorLogs(300);
    const failedSyncs = usersWithBan.flatMap((user) => syncHistoryStore_1.syncHistoryStore
        .listByUser(user.id)
        .filter((item) => item.status === 'failed')
        .slice(0, 5)
        .map((item) => ({
        id: item.id,
        source: 'creator-sync',
        message: item.message || `Sync failed for ${item.title}`,
        level: 'error',
        createdAt: item.createdAt,
        meta: item.videoId || item.videoUrl,
    })));
    const errorLogs = [...storedErrors, ...failedSyncs]
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .slice(0, 300);
    return {
        summary: {
            usersTotal: usersWithBan.length,
            videosTotal: videos.length,
            bundlesTotal: bundleRows.length,
            verification,
            creatorSubscriptions: creatorSubscriptionRows.filter((row) => row.creatorAccess).length,
            bannedUsers: usersWithBan.filter((row) => row.banned).length,
            openReports: reports.filter((report) => report.status === 'open').length,
            usageEventsTotal: usageEvents.length,
            errorLogsTotal: errorLogs.length,
            latestToolVersion: toolVersions.find((item) => item.isLatest)?.version ?? null,
        },
        users: usersWithBan,
        videos,
        bundles: bundleRows,
        reports,
        errorLogs,
        toolVersions,
        usageEvents,
        creatorSubscriptionRows,
    };
}
function buildTempPassword() {
    const token = crypto_1.default.randomBytes(6).toString('base64url');
    return `Origin!${token}`;
}
async function persistVerificationUpdate(video, originVerified, description) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        await prisma_1.prisma.video.update({
            where: { id: video.id },
            data: {
                originVerified,
                description,
            },
        });
        return;
    }
    const existing = store_1.db.videos.get(video.id);
    if (!existing)
        return;
    store_1.db.videos.set(video.id, {
        ...existing,
        originVerified,
        description,
    });
}
async function reverifyVideoAgainstLedger(video, options) {
    if (!video.originBundleId) {
        return { ok: false, status: 'skipped', reason: 'Video has no Origin bundle id.' };
    }
    const creator = await (0, userRepository_1.findUserById)(video.creatorId);
    if (!creator?.creatorKeyId) {
        return { ok: false, status: 'skipped', reason: 'Creator has no active key id.' };
    }
    const allowKeyFallback = options?.allowKeyFallback !== false;
    const strictRevocation = options?.strictRevocation === true;
    const adminOverrideOnFailure = options?.adminOverrideOnFailure === true;
    const existingHash = (0, videoVerificationService_1.extractFingerprintContentHash)(video.description);
    const contentHash = existingHash ?? (0, videoVerificationService_1.buildSyntheticFingerprint)(video.id, video.videoUrl);
    const baseDescription = existingHash
        ? (video.description ?? '')
        : (0, videoVerificationService_1.appendOriginFingerprintMetadata)(video.description, {
            contentHash,
            ownerCreatorId: video.creatorId,
        });
    const verification = await (0, videoVerificationService_1.verifyCreatorUploadAuthenticity)({
        creatorId: video.creatorId,
        keyId: creator.creatorKeyId,
        assetId: video.originBundleId,
        contentHash,
        allowKeyFallback,
        sourceLabel: strictRevocation ? 'admin revocation re-check' : 'admin verification',
    });
    const verifyResult = verification.verifyResult ?? {
        ok: false,
        reasons: [
            {
                code: 'verification_not_available',
                severity: 'warning',
                message: 'Verification result not available for this video.',
                platformAction: 'keep_unverified',
                creatorAction: 'Retry verification later.',
            },
        ],
    };
    const revokedOrInvalid = (0, videoVerificationService_1.hasRevocationOrConflictReasons)(verifyResult.reasons);
    let finalVerified = strictRevocation && revokedOrInvalid ? false : verification.originVerified;
    if (!finalVerified && adminOverrideOnFailure && !revokedOrInvalid) {
        const overrideResult = {
            ok: true,
            reasons: [
                ...(verifyResult.reasons ?? []),
                {
                    code: 'admin_override_verified',
                    severity: 'warning',
                    message: 'Admin override marked this video as verified after automated verification failed.',
                    platformAction: 'mark_verified',
                    creatorAction: 'Re-run verification later with valid Origin bundle metadata if available.',
                },
            ],
        };
        finalVerified = true;
        const overriddenDescription = (0, videoVerificationService_1.appendOriginVerificationMetadata)(baseDescription, overrideResult);
        await persistVerificationUpdate(video, true, overriddenDescription);
        return {
            ok: true,
            status: 'verified',
            reason: 'Verified via admin override fallback.',
            reasons: overrideResult.reasons,
            revokedOrInvalid,
        };
    }
    const nextDescription = (0, videoVerificationService_1.appendOriginVerificationMetadata)(baseDescription, verifyResult);
    await persistVerificationUpdate(video, finalVerified, nextDescription);
    return {
        ok: finalVerified,
        status: finalVerified ? 'verified' : 'failed',
        reasons: verifyResult.reasons,
        revokedOrInvalid,
    };
}
function parseLimit(value, fallback, max) {
    if (typeof value !== 'string')
        return fallback;
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0)
        return fallback;
    return Math.min(parsed, max);
}
function roundMoney(value) {
    return Math.round(value * 100) / 100;
}
function toMillis(value) {
    if (!value)
        return null;
    const ts = Date.parse(value);
    return Number.isFinite(ts) ? ts : null;
}
function filterVideosForVerification(videos, filters) {
    const startTs = toMillis(filters.startDate);
    const endTs = toMillis(filters.endDate);
    const includeIds = filters.videoIds ? new Set(filters.videoIds) : null;
    return videos.filter((video) => {
        if (!video.originBundleId)
            return false;
        if (filters.creatorId && video.creatorId !== filters.creatorId)
            return false;
        if (filters.unverifiedOnly && video.originVerified)
            return false;
        if (filters.onlyVerified && !video.originVerified)
            return false;
        if (includeIds && !includeIds.has(video.id))
            return false;
        const createdTs = Date.parse(video.createdAt);
        if (startTs !== null && Number.isFinite(createdTs) && createdTs < startTs)
            return false;
        if (endTs !== null && Number.isFinite(createdTs) && createdTs > endTs)
            return false;
        return true;
    });
}
router.get('/dashboard', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const payload = await buildOverviewPayload();
    const usageByMetric = payload.usageEvents.reduce((acc, event) => {
        acc[event.metric] = (acc[event.metric] ?? 0) + event.value;
        return acc;
    }, {});
    res.json({
        admin: { email: admin.email },
        summary: payload.summary,
        users: payload.users,
        videos: payload.videos,
        bundles: payload.bundles,
        reports: payload.reports,
        errorLogs: payload.errorLogs,
        toolVersions: payload.toolVersions,
        usage: {
            events: payload.usageEvents.slice(0, 300),
            byMetric: usageByMetric,
        },
        billing: {
            provider: 'stripe',
            creatorSubscriptions: payload.creatorSubscriptionRows,
            meterId: config_1.config.membership.stripeMeterId || null,
            meterEventName: config_1.config.membership.stripeMeterEventName,
        },
    });
});
router.get('/overview', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const payload = await buildOverviewPayload();
    res.json({ admin: { email: admin.email }, summary: payload.summary });
});
router.get('/users', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const limit = parseLimit(req.query.limit, 300, 1000);
    const users = await loadAdminUsers(limit);
    res.json({ items: users });
});
router.get('/videos', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const limit = parseLimit(req.query.limit, 250, 1000);
    const feed = await (0, videoRepository_1.listFeed)(1, limit);
    res.json({ items: feed.items, verification: computeVerification(feed.items) });
});
router.get('/reports', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const limit = parseLimit(req.query.limit, 300, 2000);
    const reports = adminStore_1.adminStore.listReports('all', limit);
    res.json({ items: reports, open: reports.filter((report) => report.status === 'open').length });
});
router.get('/bundles', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const limit = parseLimit(req.query.limit, 250, 2000);
    const feed = await (0, videoRepository_1.listFeed)(1, limit);
    const items = feed.items
        .filter((video) => Boolean(video.originBundleId))
        .map((video) => ({
        id: video.id,
        title: video.title,
        creatorId: video.creatorId,
        originBundleId: video.originBundleId,
        originVerified: video.originVerified,
        createdAt: video.createdAt,
    }));
    res.json({ items });
});
router.get('/usage', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const limit = parseLimit(req.query.limit, 500, 5000);
    const events = adminStore_1.adminStore.listUsageEvents(limit);
    const byMetric = events.reduce((acc, event) => {
        acc[event.metric] = (acc[event.metric] ?? 0) + event.value;
        return acc;
    }, {});
    res.json({ events, byMetric });
});
router.get('/billing', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const limit = parseLimit(req.query.limit, 300, 2000);
    const users = await loadAdminUsers(limit);
    res.json({
        provider: 'stripe',
        creatorSubscriptions: buildCreatorSubscriptionRows(users),
        meterId: config_1.config.membership.stripeMeterId || null,
        meterEventName: config_1.config.membership.stripeMeterEventName,
    });
});
router.get('/health', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const limit = parseLimit(req.query.limit, 100, 500);
    const logs = adminStore_1.adminStore.listErrorLogs(limit);
    res.json({
        status: 'ok',
        ts: new Date().toISOString(),
        recentErrors: logs,
    });
});
router.get('/recommendation/config', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    res.json({ config: adminStore_1.adminStore.getRecommendationConfig() });
});
router.patch('/recommendation/config', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = recommendationConfigUpdateSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const updated = adminStore_1.adminStore.updateRecommendationConfig(parsed.data);
    res.json({ config: updated });
});
router.get('/payouts/config', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    res.json({ config: adminStore_1.adminStore.getPayoutConfig() });
});
router.patch('/payouts/config', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = payoutConfigUpdateSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const updated = adminStore_1.adminStore.updatePayoutConfig(parsed.data);
    res.json({ config: updated });
});
router.get('/payouts/history', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const limit = parseLimit(req.query.limit, 24, 120);
    res.json({ items: adminStore_1.adminStore.listPayoutRuns(limit) });
});
router.get('/payouts/flags', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const status = typeof req.query.status === 'string' ? req.query.status : 'all';
    const normalized = status === 'open' || status === 'reviewed' || status === 'cleared' ? status : 'all';
    const limit = parseLimit(req.query.limit, 200, 5000);
    res.json({ items: adminStore_1.adminStore.listFlaggedAccounts(normalized, limit) });
});
router.patch('/payouts/flags/:userId', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = payoutFlagSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const updated = adminStore_1.adminStore.upsertFlaggedAccount({
        userId: req.params.userId,
        reason: parsed.data.reason,
        status: parsed.data.status,
    });
    res.json({ item: updated });
});
router.post('/payouts/run', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = payoutRunSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const cfg = adminStore_1.adminStore.getPayoutConfig();
    const latest = adminStore_1.adminStore.getLatestPayoutRun();
    const rolloverIn = latest?.computed.rolloverToNextMonth ?? 0;
    const payload = parsed.data;
    const costs = payload.infrastructureCost + payload.operatingCost;
    const netProfit = roundMoney(payload.totalRevenue - costs);
    const financialThresholdMet = netProfit >= cfg.thresholds.minMonthlyNetProfit
        || payload.totalRevenue >= cfg.thresholds.minMonthlyRevenue;
    const userbaseThresholdMet = payload.activeMonthlyUsers >= cfg.thresholds.minActiveMonthlyUsers
        || payload.activeCreators >= cfg.thresholds.minActiveCreators;
    const usageThresholdMet = payload.monthlyApiVerifications >= cfg.thresholds.minMonthlyApiVerifications;
    const payoutsActive = cfg.enabled && (financialThresholdMet || userbaseThresholdMet || usageThresholdMet);
    const contributions = {
        subscriptions: roundMoney(payload.subscriptionRevenue * cfg.percentages.subscriptionRevenuePct),
        apiUsage: roundMoney(payload.apiUsageRevenue * cfg.percentages.apiUsageRevenuePct),
        boosts: roundMoney(payload.boostRevenue * cfg.percentages.boostRevenuePct),
        profitShare: roundMoney(Math.max(netProfit, 0) * cfg.percentages.monthlyProfitPct),
    };
    const contributionTotal = roundMoney(contributions.subscriptions
        + contributions.apiUsage
        + contributions.boosts
        + contributions.profitShare);
    const poolBeforeDistribution = roundMoney(Math.max(0, rolloverIn + contributionTotal));
    const feed = await (0, videoRepository_1.listFeed)(1, 5000);
    const creatorEligibleViews = new Map();
    for (const video of feed.items) {
        if (!video.originVerified)
            continue;
        if (adminStore_1.adminStore.isCreatorFlagged(video.creatorId))
            continue;
        creatorEligibleViews.set(video.creatorId, (creatorEligibleViews.get(video.creatorId) ?? 0) + Math.max(0, video.viewCount));
    }
    const totalEligibleViews = [...creatorEligibleViews.values()].reduce((sum, value) => sum + value, 0);
    const payoutPerView = payoutsActive && totalEligibleViews > 0
        ? roundMoney(poolBeforeDistribution / totalEligibleViews)
        : 0;
    const creators = [...creatorEligibleViews.entries()]
        .map(([creatorId, views]) => ({
        creatorId,
        eligibleViews: views,
        estimatedPayout: roundMoney(views * payoutPerView),
    }))
        .sort((a, b) => b.estimatedPayout - a.estimatedPayout);
    const distributedTotal = roundMoney(creators.reduce((sum, row) => sum + row.estimatedPayout, 0));
    const rolloverToNextMonth = roundMoney(Math.max(0, poolBeforeDistribution - distributedTotal));
    const reason = !cfg.enabled
        ? 'Payouts are globally disabled by admin.'
        : payoutsActive
            ? 'At least one activation threshold met. Distribution active.'
            : 'Thresholds not met. Pool accrued and rolled over.';
    const created = adminStore_1.adminStore.appendPayoutRun({
        monthKey: payload.monthKey,
        inputs: {
            totalRevenue: payload.totalRevenue,
            infrastructureCost: payload.infrastructureCost,
            operatingCost: payload.operatingCost,
            subscriptionRevenue: payload.subscriptionRevenue,
            apiUsageRevenue: payload.apiUsageRevenue,
            boostRevenue: payload.boostRevenue,
            activeMonthlyUsers: payload.activeMonthlyUsers,
            activeCreators: payload.activeCreators,
            monthlyApiVerifications: payload.monthlyApiVerifications,
        },
        computed: {
            netProfit,
            contributions,
            creatorPoolBeforeDistribution: poolBeforeDistribution,
            payoutPerView,
            totalEligibleViews,
            distributedTotal,
            rolloverToNextMonth,
            activation: {
                globallyEnabled: cfg.enabled,
                financialThresholdMet,
                userbaseThresholdMet,
                usageThresholdMet,
                payoutsActive,
                reason,
            },
        },
        creators,
    });
    res.status(201).json({ item: created });
});
router.get('/tool-versions', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    res.json({ items: adminStore_1.adminStore.listToolVersions() });
});
router.post('/tool-versions', auth_1.requireAuth, toolUpload.single('file'), async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const rawBody = req.body;
    const parsed = createToolVersionSchema.safeParse({
        version: rawBody.version,
        notes: rawBody.notes,
        fileName: rawBody.fileName ?? req.file?.originalname,
        isLatest: typeof rawBody.isLatest === 'string' ? rawBody.isLatest === 'true' : rawBody.isLatest,
        forceUpdate: typeof rawBody.forceUpdate === 'string' ? rawBody.forceUpdate === 'true' : rawBody.forceUpdate,
    });
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const created = adminStore_1.adminStore.createToolVersion(parsed.data);
    res.status(201).json({ item: created });
});
router.patch('/tool-versions/:id', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = updateToolVersionSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const updated = adminStore_1.adminStore.updateToolVersion(req.params.id, parsed.data);
    if (!updated) {
        res.status(404).json({ error: 'Version not found' });
        return;
    }
    res.json({ item: updated });
});
router.post('/tool-versions/:id/download', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const updated = adminStore_1.adminStore.incrementToolVersionDownload(req.params.id);
    if (!updated) {
        res.status(404).json({ error: 'Version not found' });
        return;
    }
    res.json({ item: updated });
});
router.patch('/users/:id/creator-access', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = creatorAccessSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const target = await (0, userRepository_1.findUserById)(req.params.id);
    if (!target) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    const updated = await (0, userRepository_2.updateUser)(target.id, {
        creatorKeyId: parsed.data.active ? (target.creatorKeyId ?? buildCreatorKeyId(target.id)) : null,
    });
    if (!updated) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    res.json({
        user: {
            id: updated.id,
            email: updated.email,
            displayName: updated.displayName,
            creatorKeyId: updated.creatorKeyId,
        },
    });
});
router.patch('/users/:id/admin', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = adminRoleSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const target = await (0, userRepository_1.findUserById)(req.params.id);
    if (!target) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    if (target.id === admin.id && !parsed.data.active) {
        res.status(400).json({ error: 'You cannot remove your own admin access.' });
        return;
    }
    adminStore_1.adminStore.setPromotedAdmin(target.id, parsed.data.active);
    res.json({
        userId: target.id,
        isAdmin: isUserAdmin({ id: target.id, email: target.email }),
    });
});
router.delete('/videos/:id', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const existing = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!existing) {
        res.status(404).json({ error: 'Video not found' });
        return;
    }
    await (0, videoRepository_1.deleteVideo)(existing.id);
    res.status(204).send();
});
router.post('/videos/:id/verify-now', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = verifyNowSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const video = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!video) {
        res.status(404).json({ error: 'Video not found' });
        return;
    }
    if (video.originVerified && !parsed.data.force) {
        res.json({
            videoId: video.id,
            status: 'skipped',
            reason: 'Video already verified. Pass { force: true } to re-run.',
        });
        return;
    }
    const result = await reverifyVideoAgainstLedger(video, {
        allowKeyFallback: parsed.data.allowKeyFallback !== false,
        adminOverrideOnFailure: parsed.data.allowAdminOverrideOnFailure !== false,
    });
    const refreshed = await (0, videoRepository_1.getVideoById)(video.id);
    res.json({
        videoId: video.id,
        status: result.status,
        ok: result.ok,
        reason: result.reason,
        reasons: result.reasons ?? [],
        video: refreshed,
    });
});
router.post('/videos/verify-bulk', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = verifyBulkSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const limit = parsed.data.limit ?? 200;
    const feed = await (0, videoRepository_1.listFeed)(1, 2000);
    const candidates = filterVideosForVerification(feed.items, {
        creatorId: parsed.data.creatorId,
        startDate: parsed.data.startDate,
        endDate: parsed.data.endDate,
        unverifiedOnly: parsed.data.unverifiedOnly !== false,
        videoIds: parsed.data.videoIds,
    }).slice(0, limit);
    let verified = 0;
    let failed = 0;
    let skipped = 0;
    const details = [];
    for (const video of candidates) {
        const result = await reverifyVideoAgainstLedger(video, {
            allowKeyFallback: parsed.data.allowKeyFallback !== false,
            adminOverrideOnFailure: parsed.data.allowAdminOverrideOnFailure !== false,
        });
        if (result.status === 'verified')
            verified += 1;
        if (result.status === 'failed')
            failed += 1;
        if (result.status === 'skipped')
            skipped += 1;
        details.push({
            videoId: video.id,
            title: video.title,
            status: result.status,
            reason: result.reason,
        });
    }
    res.json({
        processed: candidates.length,
        verified,
        failed,
        skipped,
        details,
    });
});
router.post('/videos/recheck-revocations', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = recheckRevocationsSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const limit = parsed.data.limit ?? 200;
    const feed = await (0, videoRepository_1.listFeed)(1, 2000);
    const candidates = filterVideosForVerification(feed.items, {
        creatorId: parsed.data.creatorId,
        startDate: parsed.data.startDate,
        endDate: parsed.data.endDate,
        onlyVerified: parsed.data.onlyVerified !== false,
        videoIds: parsed.data.videoIds,
    }).slice(0, limit);
    let checked = 0;
    let revokedOrInvalid = 0;
    let stillVerified = 0;
    let failed = 0;
    let skipped = 0;
    const details = [];
    for (const video of candidates) {
        const result = await reverifyVideoAgainstLedger(video, {
            allowKeyFallback: false,
            strictRevocation: true,
        });
        checked += 1;
        if (result.status === 'verified')
            stillVerified += 1;
        if (result.status === 'failed')
            failed += 1;
        if (result.status === 'skipped')
            skipped += 1;
        if (result.revokedOrInvalid)
            revokedOrInvalid += 1;
        details.push({
            videoId: video.id,
            title: video.title,
            status: result.status,
            revokedOrInvalid: result.revokedOrInvalid,
            reason: result.reason,
        });
    }
    res.json({
        checked,
        stillVerified,
        revokedOrInvalid,
        failed,
        skipped,
        details,
    });
});
// Backward-compatible aliases.
router.post('/videos/:id/reverify', auth_1.requireAuth, async (req, res) => {
    req.url = `/videos/${req.params.id}/verify-now`;
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = verifyNowSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const video = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!video) {
        res.status(404).json({ error: 'Video not found' });
        return;
    }
    if (video.originVerified && !parsed.data.force) {
        res.json({
            videoId: video.id,
            status: 'skipped',
            reason: 'Video already verified. Pass { force: true } to re-run.',
            ok: false,
            reasons: [],
            video,
        });
        return;
    }
    const result = await reverifyVideoAgainstLedger(video, {
        allowKeyFallback: parsed.data.allowKeyFallback !== false,
        adminOverrideOnFailure: parsed.data.allowAdminOverrideOnFailure !== false,
    });
    const refreshed = await (0, videoRepository_1.getVideoById)(video.id);
    res.json({
        videoId: video.id,
        status: result.status,
        ok: result.ok,
        reason: result.reason,
        reasons: result.reasons ?? [],
        video: refreshed,
    });
});
router.post('/verification/reverify-failed', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = reverifyFailedSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const feed = await (0, videoRepository_1.listFeed)(1, 2000);
    const candidates = filterVideosForVerification(feed.items, {
        unverifiedOnly: !Boolean(parsed.data.includeVerified),
    }).slice(0, parsed.data.limit ?? 120);
    let verified = 0;
    let failed = 0;
    let skipped = 0;
    const details = [];
    for (const video of candidates) {
        const result = await reverifyVideoAgainstLedger(video, {
            allowKeyFallback: true,
            adminOverrideOnFailure: true,
        });
        if (result.status === 'verified')
            verified += 1;
        if (result.status === 'failed')
            failed += 1;
        if (result.status === 'skipped')
            skipped += 1;
        details.push({
            videoId: video.id,
            title: video.title,
            status: result.status,
            reason: result.reason,
        });
    }
    res.json({ processed: candidates.length, verified, failed, skipped, details });
});
router.patch('/users/:id/ban', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = banSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const target = await (0, userRepository_1.findUserById)(req.params.id);
    if (!target) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    adminStore_1.adminStore.setUserBan(target.id, parsed.data.banned);
    res.json({ userId: target.id, banned: parsed.data.banned });
});
router.post('/users/:id/reset-password', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const target = await (0, userRepository_1.findUserById)(req.params.id);
    if (!target) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    const temporaryPassword = buildTempPassword();
    const passwordHash = await bcryptjs_1.default.hash(temporaryPassword, 10);
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        await prisma_1.prisma.user.update({ where: { id: target.id }, data: { passwordHash } });
    }
    else {
        const current = store_1.db.users.get(target.id);
        if (!current) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        store_1.db.users.set(target.id, { ...current, passwordHash });
    }
    res.json({ userId: target.id, temporaryPassword });
});
router.patch('/reports/:id', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const parsed = resolveReportSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const updated = adminStore_1.adminStore.resolveReport(req.params.id, admin.id);
    if (!updated) {
        res.status(404).json({ error: 'Report not found' });
        return;
    }
    res.json({ item: updated });
});
router.get('/export/usage.csv', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const rows = adminStore_1.adminStore.listUsageEvents(5000);
    const header = 'id,metric,value,userId,source,createdAt';
    const body = rows.map((row) => [
        row.id,
        row.metric,
        String(row.value),
        row.userId ?? '',
        row.source ?? '',
        row.createdAt,
    ].map((value) => `"${String(value).replace(/"/g, '""')}"`).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="origin-usage.csv"');
    res.send(`${header}\n${body}`);
});
router.get('/export/billing.csv', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const banned = new Set(adminStore_1.adminStore.listBannedUserIds());
    const users = config_1.config.database.usePrisma && prisma_1.prisma
        ? (await prisma_1.prisma.user.findMany({
            orderBy: { createdAt: 'desc' },
            take: 5000,
            select: { id: true, username: true, email: true, displayName: true, creatorKeyId: true, createdAt: true },
        })).map((user) => ({
            ...user,
            createdAt: user.createdAt.toISOString(),
        }))
        : [...store_1.db.users.values()].map((user) => ({
            id: user.id,
            username: user.username,
            email: user.email,
            displayName: user.displayName,
            creatorKeyId: user.creatorKeyId,
            createdAt: user.createdAt,
        }));
    const header = 'userId,email,displayName,creatorAccess,banned,createdAt';
    const body = users.map((row) => [
        row.id,
        row.email,
        row.displayName,
        row.creatorKeyId ? 'true' : 'false',
        banned.has(row.id) ? 'true' : 'false',
        row.createdAt,
    ].map((value) => `"${String(value).replace(/"/g, '""')}"`).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="origin-billing.csv"');
    res.send(`${header}\n${body}`);
});
router.get('/protocol/bundles/:bundleId', auth_1.requireAuth, async (req, res) => {
    const admin = await requireAdmin(req, res);
    if (!admin)
        return;
    const bundleId = req.params.bundleId.trim();
    const feed = await (0, videoRepository_1.listFeed)(1, 2000);
    const match = feed.items.find((video) => (video.originBundleId ?? '').trim() === bundleId);
    if (!match) {
        res.status(404).json({ error: 'Bundle not found' });
        return;
    }
    const reasonCodes = (match.originReasons ?? []).map((reason) => reason.code);
    const signatureFailure = reasonCodes.includes('signature_invalid') || reasonCodes.includes('signature_failure');
    const fingerprintMismatch = reasonCodes.includes('fingerprint_mismatch');
    const assetIdCollision = reasonCodes.includes('asset_id_collision');
    res.json({
        bundleId,
        videoId: match.id,
        title: match.title,
        creatorId: match.creatorId,
        originVerified: match.originVerified,
        createdAt: match.createdAt,
        contentHash: (0, videoVerificationService_1.extractFingerprintContentHash)(match.description),
        manifestHash: (0, videoVerificationService_1.extractFingerprintContentHash)(match.description),
        checks: {
            signatureFailure,
            fingerprintMismatch,
            assetIdCollision,
            gFilterReveal: Boolean(match.originBundleId),
        },
        verificationReasons: match.originReasons ?? [],
    });
});
exports.default = router;
//# sourceMappingURL=admin.js.map