"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const uuid_1 = require("uuid");
const zod_1 = require("zod");
const auth_1 = require("../middleware/auth");
const errorHandler_1 = require("../middleware/errorHandler");
const store_1 = require("../models/store");
const prisma_1 = require("../models/prisma");
const originService_1 = require("../services/originService");
const cloudflareStreamService_1 = require("../services/cloudflareStreamService");
const storageService_1 = require("../services/storageService");
const config_1 = require("../config");
const videoRepository_1 = require("../repositories/videoRepository");
const userRepository_1 = require("../repositories/userRepository");
const adminStore_1 = require("../services/adminStore");
const contentModerationService_1 = require("../services/contentModerationService");
const messagingStore_1 = require("../services/messagingStore");
const videoVerificationService_1 = require("../services/videoVerificationService");
const router = (0, express_1.Router)();
const upload = (0, storageService_1.createVideoUploadMulter)();
const uploadSchema = zod_1.z.object({
    title: zod_1.z.string().min(1).max(150),
    description: zod_1.z.string().max(500).optional(),
    originBundleId: zod_1.z.string().optional(),
    assetId: zod_1.z.string().optional(),
    keyId: zod_1.z.string().optional(),
    contentHash: zod_1.z.string().optional(),
    originId: zod_1.z.string().optional(),
    protectedUpload: zod_1.z.coerce.boolean().optional(),
    protectionOptions: zod_1.z.union([zod_1.z.array(zod_1.z.string()), zod_1.z.string()]).optional(),
    intendedPlatforms: zod_1.z.union([zod_1.z.array(zod_1.z.string()), zod_1.z.string()]).optional(),
    originPolicy: zod_1.z.string().optional(),
    governanceLedgerCid: zod_1.z.string().optional(),
});
const sealedIngestSchema = zod_1.z.object({
    creatorId: zod_1.z.string().optional(),
    title: zod_1.z.string().min(1).max(150),
    description: zod_1.z.string().max(500).optional(),
    videoUrl: zod_1.z.string().min(1),
    originBundleId: zod_1.z.string().optional(),
    assetId: zod_1.z.string().optional(),
    keyId: zod_1.z.string().optional(),
    contentHash: zod_1.z.string().optional(),
    originId: zod_1.z.string().optional(),
    originPolicy: zod_1.z.string().optional(),
    governanceLedgerCid: zod_1.z.string().optional(),
});
const cloudflareDirectUploadSchema = zod_1.z.object({
    title: zod_1.z.string().min(1).max(150),
});
const cloudflareFinalizeSchema = zod_1.z.object({
    uid: zod_1.z.string().min(1),
    title: zod_1.z.string().min(1).max(150),
    description: zod_1.z.string().max(500).optional(),
    originBundleId: zod_1.z.string().optional(),
    assetId: zod_1.z.string().optional(),
    keyId: zod_1.z.string().optional(),
    contentHash: zod_1.z.string().optional(),
    originId: zod_1.z.string().optional(),
    protectedUpload: zod_1.z.boolean().optional(),
    protectionOptions: zod_1.z.array(zod_1.z.string()).optional(),
    intendedPlatforms: zod_1.z.array(zod_1.z.string()).optional(),
    originPolicy: zod_1.z.string().optional(),
    governanceLedgerCid: zod_1.z.string().optional(),
});
const reportVideoSchema = zod_1.z.object({
    reason: zod_1.z.string().min(3).max(140),
    notes: zod_1.z.string().max(1000).optional(),
});
const ORIGIN_PROTECTION_MARKER = '[origin_protection]';
const ORIGIN_POLICY_VALUES = new Set(['permissive', 'standard', 'strict']);
function hasText(value) {
    return Boolean(value && value.trim());
}
function parseStringList(value) {
    if (!value)
        return [];
    if (Array.isArray(value)) {
        return value.map((item) => `${item}`.trim()).filter(Boolean);
    }
    try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) {
            return parsed.map((item) => `${item}`.trim()).filter(Boolean);
        }
    }
    catch {
        // no-op
    }
    return value
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
}
function normalizeToken(value) {
    const normalized = (value ?? '').trim().toLowerCase();
    return normalized.length > 0 ? normalized : null;
}
function normalizeOriginPolicy(value) {
    const normalized = (value ?? '').trim().toLowerCase();
    if (!normalized)
        return null;
    return ORIGIN_POLICY_VALUES.has(normalized) ? normalized : null;
}
function deriveOriginPolicyFromProtectionOptions(value) {
    const options = parseStringList(value);
    for (const option of options) {
        const normalized = option.trim().toLowerCase();
        const candidate = normalized.startsWith('policy:')
            ? normalized.slice('policy:'.length)
            : normalized.startsWith('policy-')
                ? normalized.slice('policy-'.length)
                : null;
        if (candidate && ORIGIN_POLICY_VALUES.has(candidate)) {
            return candidate;
        }
    }
    return null;
}
function ensureOriginProtectionMetadata(description, params) {
    const hasAny = Boolean(params.originPolicy || params.governanceLedgerCid || params.protectionOptions.length > 0);
    if (!hasAny)
        return description;
    if ((description ?? '').includes(ORIGIN_PROTECTION_MARKER))
        return description;
    const payload = {
        protected: true,
        policyProfile: params.originPolicy ?? 'standard',
        governanceLedgerCid: params.governanceLedgerCid ?? undefined,
        options: params.protectionOptions,
        platforms: params.intendedPlatforms,
    };
    const encoded = JSON.stringify(payload);
    const base = (description ?? '').trim();
    return base
        ? `${base}\n\n${ORIGIN_PROTECTION_MARKER}${encoded}`
        : `${ORIGIN_PROTECTION_MARKER}${encoded}`;
}
function extractSharedWithCreators(description) {
    const parsed = (0, videoVerificationService_1.extractMarkerJson)(description, ORIGIN_PROTECTION_MARKER);
    const ids = Array.isArray(parsed?.sharedWithCreators) ? parsed.sharedWithCreators : [];
    return new Set(ids
        .map((item) => item.trim())
        .filter(Boolean));
}
async function enforceProtectedReuploadPolicy(params) {
    const incomingBundleId = normalizeToken(params.incomingBundleId);
    const incomingContentHash = normalizeToken(params.incomingContentHash);
    if (!incomingBundleId && !incomingContentHash) {
        return;
    }
    const protectedVideos = await (0, videoRepository_1.listProtectedVideoCandidates)();
    for (const existing of protectedVideos) {
        if (existing.creatorId === params.uploaderCreatorId)
            continue;
        const sharedWith = extractSharedWithCreators(existing.description);
        if (sharedWith.has(params.uploaderCreatorId))
            continue;
        const existingBundleId = normalizeToken(existing.originBundleId);
        const existingContentHash = (0, videoVerificationService_1.extractFingerprintContentHash)(existing.description);
        const bundleConflict = Boolean(incomingBundleId && existingBundleId && incomingBundleId === existingBundleId);
        const hashConflict = Boolean(incomingContentHash && existingContentHash && incomingContentHash === existingContentHash);
        if (bundleConflict || hashConflict) {
            throw new errorHandler_1.HttpError(409, `Protected content match detected with \"${existing.title}\". Re-upload is blocked unless the creator shares permission.`);
        }
    }
}
function isProtectionMarkerPresent(value) {
    if (!value)
        return false;
    return value.toLowerCase().includes('[origin_protection]');
}
function extractLeadingMentionUsername(text) {
    const match = text.trim().match(/^@([a-zA-Z0-9_\.\-]{2,40})\b/);
    return match ? match[1] : null;
}
function notifyUploadPublished(creatorId, video) {
    messagingStore_1.messagingStore.createNotification({
        userId: creatorId,
        type: 'social_status',
        title: 'Your post is live',
        body: `"${video.title}" is now published on Origin.`,
        data: {
            videoId: video.id,
            creatorId,
        },
    });
    const audience = messagingStore_1.messagingStore.listCreatorUploadAudience(creatorId);
    for (const item of audience) {
        if (item.userId === creatorId)
            continue;
        messagingStore_1.messagingStore.createNotification({
            userId: item.userId,
            type: 'creator_upload',
            title: 'New creator upload',
            body: `A creator you follow posted: ${video.title}`,
            channel: item.channel,
            data: {
                videoId: video.id,
                creatorId,
            },
        });
    }
}
function isProtectedUploadRequest(payload) {
    return Boolean(payload.protectedUpload ||
        hasText(payload.originBundleId) ||
        isProtectionMarkerPresent(payload.description));
}
function hasOriginProofRequest(payload) {
    return Boolean(payload.protectedUpload ||
        hasText(payload.originBundleId) ||
        hasText(payload.assetId) ||
        hasText(payload.keyId) ||
        hasText(payload.contentHash) ||
        isProtectionMarkerPresent(payload.description));
}
async function enforceMembershipForProtectedUpload(creatorId) {
    const creator = config_1.config.database.usePrisma && prisma_1.prisma
        ? await prisma_1.prisma.user.findUnique({ where: { id: creatorId } })
        : store_1.db.users.get(creatorId);
    if (!creator?.creatorKeyId) {
        throw new errorHandler_1.HttpError(403, 'Creator protection requires active membership');
    }
}
function validateSealedOriginEvidence(payload) {
    const hasBundle = hasText(payload.originBundleId);
    const hasAsset = hasText(payload.assetId);
    const hasKey = hasText(payload.keyId);
    const hasHash = hasText(payload.contentHash);
    const wantsProof = hasBundle || hasAsset || hasKey || hasHash;
    if (!wantsProof)
        return [];
    const missing = [];
    if (!hasBundle)
        missing.push('originBundleId');
    if (!hasAsset)
        missing.push('assetId');
    if (!hasKey)
        missing.push('keyId');
    if (!hasHash)
        missing.push('contentHash');
    return missing;
}
async function verifySealedOriginProof(creatorId, payload) {
    const hasBundle = hasText(payload.originBundleId);
    const hasAsset = hasText(payload.assetId);
    const hasKey = hasText(payload.keyId);
    const hasHash = hasText(payload.contentHash);
    if (!(hasBundle && hasAsset && hasKey && hasHash)) {
        return null;
    }
    try {
        return await originService_1.originService.verify({
            creatorId,
            keyId: payload.keyId,
            assetId: payload.assetId,
            originId: payload.originId,
            contentHash: payload.contentHash,
        });
    }
    catch {
        const reasons = [
            {
                code: 'ledger_unreachable',
                severity: 'critical',
                message: 'Origin ledger could not be reached during sealed publish verification',
                platformAction: 'reject_publish',
                creatorAction: 'Retry later or contact support.',
            },
        ];
        return { ok: false, reasons };
    }
}
function resolveCreatorForSealedIngest(req, bodyCreatorId) {
    const ingestKey = (req.header('X-Origin-Ingest-Key') ?? '').trim();
    if (config_1.config.ingest.apiKey && ingestKey && ingestKey === config_1.config.ingest.apiKey) {
        if (!bodyCreatorId) {
            throw new errorHandler_1.HttpError(400, 'creatorId is required when using ingest API key');
        }
        return bodyCreatorId;
    }
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
        throw new errorHandler_1.HttpError(401, 'Missing authentication (Bearer token or valid ingest key)');
    }
    const token = header.slice(7);
    try {
        const payload = jsonwebtoken_1.default.verify(token, config_1.config.jwt.secret);
        return payload.sub;
    }
    catch {
        throw new errorHandler_1.HttpError(401, 'Invalid or expired token');
    }
}
async function handleSealedPublish(req, res) {
    const parsed = sealedIngestSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const payload = parsed.data;
    const originPolicy = normalizeOriginPolicy(payload.originPolicy);
    const governanceLedgerCid = normalizeToken(payload.governanceLedgerCid) ?? null;
    const creatorId = resolveCreatorForSealedIngest(req, payload.creatorId);
    const moderationDecision = await contentModerationService_1.contentModerationService.evaluate({
        creatorId,
        title: payload.title,
        description: payload.description,
        videoUrl: payload.videoUrl,
        source: 'sealed',
    });
    if (!moderationDecision.allowed) {
        adminStore_1.adminStore.appendErrorLog({
            source: 'content-moderation',
            level: 'warning',
            message: moderationDecision.reason || 'Blocked by content moderation policy',
            meta: JSON.stringify({ provider: moderationDecision.provider, categories: moderationDecision.categories }),
        });
        throw new errorHandler_1.HttpError(422, 'Upload blocked by platform content policy (adult/sexual content is not allowed).');
    }
    await enforceProtectedReuploadPolicy({
        uploaderCreatorId: creatorId,
        incomingBundleId: payload.originBundleId,
        incomingContentHash: payload.contentHash,
    });
    const missingEvidence = validateSealedOriginEvidence(payload);
    if (missingEvidence.length > 0) {
        res.status(400).json({
            error: `Incomplete Origin proof payload for sealed publish. Missing: ${missingEvidence.join(', ')}`,
        });
        return;
    }
    let originVerified = false;
    const verifyResult = await verifySealedOriginProof(creatorId, payload);
    if (verifyResult) {
        originVerified = verifyResult.ok;
        if (!verifyResult.ok) {
            res.status(422).json({
                error: 'Origin proof verification failed for sealed publish',
                reasons: verifyResult.reasons,
            });
            return;
        }
    }
    const now = new Date().toISOString();
    const id = (0, uuid_1.v4)();
    const video = {
        id,
        creatorId,
        title: payload.title,
        description: verifyResult
            ? (0, videoVerificationService_1.appendOriginVerificationMetadata)(ensureOriginProtectionMetadata(payload.description, {
                originPolicy,
                governanceLedgerCid,
                protectionOptions: [],
                intendedPlatforms: [],
            }), verifyResult)
            : ensureOriginProtectionMetadata(payload.description, {
                originPolicy,
                governanceLedgerCid,
                protectionOptions: [],
                intendedPlatforms: [],
            }) ?? null,
        videoUrl: payload.videoUrl,
        thumbnailUrl: null,
        duration: null,
        likeCount: 0,
        commentCount: 0,
        viewCount: 0,
        originBundleId: payload.originBundleId ?? null,
        originPolicy,
        governanceLedgerCid,
        originVerified,
        createdAt: now,
    };
    const created = await (0, videoRepository_1.createVideo)(video);
    notifyUploadPublished(creatorId, { id: created.id, title: created.title });
    res.status(201).json({ video: created, sync: 'creator-tool' });
}
// POST /api/videos/sealed
// Creator-tool integration: publish already-sealed assets without multipart upload.
router.post('/sealed', async (req, res) => {
    await handleSealedPublish(req, res);
});
// POST /api/videos/sync/sealed
// Phase 3 sync endpoint for creator-tool -> platform handoff.
router.post('/sync/sealed', async (req, res) => {
    await handleSealedPublish(req, res);
});
// POST /api/videos/cloudflare/direct-upload
router.post('/cloudflare/direct-upload', auth_1.requireAuth, async (req, res) => {
    const parsed = cloudflareDirectUploadSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const result = await cloudflareStreamService_1.cloudflareStreamService.createDirectUpload({
        creatorId: req.userId,
        title: parsed.data.title,
    });
    res.json({
        uid: result.uid,
        uploadURL: result.uploadURL,
        playbackBase: config_1.config.cloudflareStream.subdomain || 'videodelivery.net',
    });
});
// POST /api/videos/cloudflare/finalize
router.post('/cloudflare/finalize', auth_1.requireAuth, async (req, res) => {
    const parsed = cloudflareFinalizeSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const payload = parsed.data;
    const originPolicy = normalizeOriginPolicy(payload.originPolicy) ?? deriveOriginPolicyFromProtectionOptions(payload.protectionOptions);
    const governanceLedgerCid = normalizeToken(payload.governanceLedgerCid) ?? null;
    const proofRequested = hasOriginProofRequest(payload);
    if (proofRequested) {
        await enforceMembershipForProtectedUpload(req.userId);
    }
    await enforceProtectedReuploadPolicy({
        uploaderCreatorId: req.userId,
        incomingBundleId: payload.originBundleId,
        incomingContentHash: payload.contentHash,
    });
    const moderationDecision = await contentModerationService_1.contentModerationService.evaluate({
        creatorId: req.userId,
        title: payload.title,
        description: payload.description,
        videoUrl: cloudflareStreamService_1.cloudflareStreamService.buildPlaybackUrl(payload.uid),
        streamUid: payload.uid,
        source: 'cloudflare-finalize',
    });
    if (!moderationDecision.allowed) {
        adminStore_1.adminStore.appendErrorLog({
            source: 'content-moderation',
            level: 'warning',
            message: moderationDecision.reason || 'Blocked by content moderation policy',
            meta: JSON.stringify({ provider: moderationDecision.provider, categories: moderationDecision.categories }),
        });
        throw new errorHandler_1.HttpError(422, 'Upload blocked by platform content policy (adult/sexual content is not allowed).');
    }
    const details = await cloudflareStreamService_1.cloudflareStreamService.getStreamDetails(payload.uid);
    const creator = config_1.config.database.usePrisma && prisma_1.prisma
        ? await prisma_1.prisma.user.findUnique({ where: { id: req.userId } })
        : store_1.db.users.get(req.userId);
    const resolvedAssetId = payload.assetId ?? payload.originBundleId;
    const resolvedKeyId = payload.keyId ?? creator?.creatorKeyId ?? undefined;
    const creatorVerification = resolvedKeyId
        ? await (0, videoVerificationService_1.verifyCreatorUploadAuthenticity)({
            creatorId: req.userId,
            keyId: resolvedKeyId,
            assetId: resolvedAssetId,
            originId: payload.originId,
            contentHash: payload.contentHash,
        })
        : { originVerified: false, verifyResult: null };
    if (proofRequested && !creatorVerification.originVerified) {
        res.status(422).json({
            error: 'Origin proof verification failed; protected upload must be verified before publish',
            reasons: creatorVerification.verifyResult?.reasons ?? [],
        });
        return;
    }
    const protectedDescription = ensureOriginProtectionMetadata(payload.description, {
        originPolicy,
        governanceLedgerCid,
        protectionOptions: parseStringList(payload.protectionOptions),
        intendedPlatforms: parseStringList(payload.intendedPlatforms),
    });
    const verificationDescription = creatorVerification.verifyResult
        ? (0, videoVerificationService_1.appendOriginVerificationMetadata)(protectedDescription, creatorVerification.verifyResult)
        : protectedDescription;
    const now = new Date().toISOString();
    const id = (0, uuid_1.v4)();
    const video = {
        id,
        creatorId: req.userId,
        title: payload.title,
        description: payload.contentHash
            ? (0, videoVerificationService_1.appendOriginFingerprintMetadata)(verificationDescription, {
                contentHash: payload.contentHash,
                ownerCreatorId: req.userId,
            })
            : verificationDescription ?? null,
        videoUrl: cloudflareStreamService_1.cloudflareStreamService.buildPlaybackUrl(payload.uid),
        thumbnailUrl: cloudflareStreamService_1.cloudflareStreamService.buildThumbnailUrl(payload.uid),
        duration: details.duration ?? null,
        likeCount: 0,
        commentCount: 0,
        viewCount: 0,
        originBundleId: payload.originBundleId ?? null,
        originPolicy,
        governanceLedgerCid,
        originVerified: creatorVerification.originVerified,
        createdAt: now,
    };
    const created = await (0, videoRepository_1.createVideo)(video);
    notifyUploadPublished(req.userId, { id: created.id, title: created.title });
    res.status(201).json({
        video: created,
        stream: {
            uid: payload.uid,
            readyToStream: Boolean(details.readyToStream),
        },
    });
});
// GET /api/videos/:id
router.get('/:id', async (req, res) => {
    const updated = await (0, videoRepository_1.getVideoAndIncrementView)(req.params.id);
    if (!updated)
        throw new errorHandler_1.HttpError(404, 'Video not found');
    res.json({ video: updated });
});
// GET /api/videos/:id/meta (no view increment)
router.get('/:id/meta', async (req, res) => {
    const video = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!video)
        throw new errorHandler_1.HttpError(404, 'Video not found');
    res.json({ video });
});
// POST /api/videos  (requires auth + video file)
router.post('/', auth_1.requireAuth, upload.single('video'), async (req, res) => {
    if (!req.file)
        throw new errorHandler_1.HttpError(400, 'No video file provided');
    const parsed = uploadSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const { title, description, originBundleId, assetId, keyId, protectedUpload, contentHash, originId, originPolicy: bodyOriginPolicy, governanceLedgerCid: bodyGovernanceLedgerCid } = parsed.data;
    const parsedProtectionOptions = parseStringList(parsed.data.protectionOptions);
    const parsedIntendedPlatforms = parseStringList(parsed.data.intendedPlatforms);
    const originPolicy = normalizeOriginPolicy(bodyOriginPolicy) ?? deriveOriginPolicyFromProtectionOptions(parsed.data.protectionOptions);
    const governanceLedgerCid = normalizeToken(bodyGovernanceLedgerCid) ?? null;
    const creatorId = req.userId;
    const moderationDecision = await contentModerationService_1.contentModerationService.evaluate({
        creatorId,
        title,
        description,
        source: 'direct-upload',
    });
    if (!moderationDecision.allowed) {
        adminStore_1.adminStore.appendErrorLog({
            source: 'content-moderation',
            level: 'warning',
            message: moderationDecision.reason || 'Blocked by content moderation policy',
            meta: JSON.stringify({ provider: moderationDecision.provider, categories: moderationDecision.categories }),
        });
        throw new errorHandler_1.HttpError(422, 'Upload blocked by platform content policy (adult/sexual content is not allowed).');
    }
    const creator = config_1.config.database.usePrisma && prisma_1.prisma
        ? await prisma_1.prisma.user.findUnique({ where: { id: creatorId } })
        : store_1.db.users.get(creatorId);
    const proofRequested = hasOriginProofRequest({
        protectedUpload,
        originBundleId,
        assetId,
        keyId,
        contentHash,
        description,
    });
    if (proofRequested) {
        await enforceMembershipForProtectedUpload(creatorId);
    }
    const stored = await (0, storageService_1.persistUploadedVideo)(req.file);
    let originVerified = false;
    let originVerifyResult = null;
    try {
        await enforceProtectedReuploadPolicy({
            uploaderCreatorId: creatorId,
            incomingBundleId: originBundleId,
            incomingContentHash: stored.contentHandle,
        });
    }
    catch (error) {
        await (0, storageService_1.deleteUploadedVideo)(stored.videoUrl);
        throw error;
    }
    const resolvedAssetId = assetId ?? originBundleId;
    const resolvedKeyId = keyId ?? creator?.creatorKeyId ?? undefined;
    if (resolvedKeyId) {
        const verification = await (0, videoVerificationService_1.verifyCreatorUploadAuthenticity)({
            creatorId,
            keyId: resolvedKeyId,
            assetId: resolvedAssetId,
            originId,
            contentHash: stored.contentHandle || contentHash,
        });
        originVerified = verification.originVerified;
        originVerifyResult = verification.verifyResult;
    }
    if (proofRequested && !originVerified) {
        await (0, storageService_1.deleteUploadedVideo)(stored.videoUrl);
        const reasons = originVerifyResult?.reasons ?? [
            {
                code: 'creator_key_missing_or_inactive',
                severity: 'critical',
                message: 'Protected upload requires active creator key and successful Origin verification.',
                platformAction: 'reject_publish',
                creatorAction: 'Activate/repair creator key and re-run sealed publish from Creator GUI.',
            },
        ];
        res.status(422).json({
            error: 'Origin proof verification failed; protected upload must be verified before publish',
            reasons,
        });
        return;
    }
    const protectedDescription = ensureOriginProtectionMetadata(description, {
        originPolicy,
        governanceLedgerCid,
        protectionOptions: parsedProtectionOptions,
        intendedPlatforms: parsedIntendedPlatforms,
    });
    const verifiedDescription = originVerifyResult
        ? (0, videoVerificationService_1.appendOriginVerificationMetadata)(protectedDescription, originVerifyResult)
        : protectedDescription;
    const persistedDescription = (0, videoVerificationService_1.appendOriginFingerprintMetadata)(verifiedDescription, {
        contentHash: stored.contentHandle,
        ownerCreatorId: creatorId,
    });
    const now = new Date().toISOString();
    const id = (0, uuid_1.v4)();
    const videoUrl = stored.videoUrl;
    const video = {
        id,
        creatorId,
        title,
        description: persistedDescription ?? null,
        videoUrl,
        thumbnailUrl: null,
        duration: null,
        likeCount: 0,
        commentCount: 0,
        viewCount: 0,
        originBundleId: originBundleId ?? null,
        originPolicy,
        governanceLedgerCid,
        originVerified,
        createdAt: now,
    };
    const created = await (0, videoRepository_1.createVideo)(video);
    notifyUploadPublished(creatorId, { id: created.id, title: created.title });
    res.status(201).json({ video: created });
});
// DELETE /api/videos/:id
router.delete('/:id', auth_1.requireAuth, async (req, res) => {
    const video = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!video)
        throw new errorHandler_1.HttpError(404, 'Video not found');
    if (video.creatorId !== req.userId)
        throw new errorHandler_1.HttpError(403, 'Forbidden');
    await (0, storageService_1.deleteUploadedVideo)(video.videoUrl);
    await (0, videoRepository_1.deleteVideo)(video.id);
    res.status(204).send();
});
// POST /api/videos/:id/like
router.post('/:id/like', auth_1.requireAuth, async (req, res) => {
    const video = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!video)
        throw new errorHandler_1.HttpError(404, 'Video not found');
    const liked = await (0, videoRepository_1.toggleLike)(req.userId, video.id);
    const updated = await (0, videoRepository_1.getVideoById)(video.id);
    if (liked && req.userId !== video.creatorId) {
        messagingStore_1.messagingStore.createNotification({
            userId: video.creatorId,
            type: 'video_like',
            title: 'New like on your video',
            body: `Someone liked "${video.title}".`,
            data: {
                videoId: video.id,
                actorUserId: req.userId,
            },
        });
    }
    res.json({ liked, likeCount: updated?.likeCount ?? video.likeCount });
});
// GET /api/videos/:id/comments
router.get('/:id/comments', async (req, res) => {
    const video = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!video)
        throw new errorHandler_1.HttpError(404, 'Video not found');
    const comments = await (0, videoRepository_1.listComments)(video.id);
    res.json({ comments });
});
// POST /api/videos/:id/comments
router.post('/:id/comments', auth_1.requireAuth, async (req, res) => {
    const video = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!video)
        throw new errorHandler_1.HttpError(404, 'Video not found');
    const text = (req.body?.text ?? '').toString().trim();
    if (!text || text.length > 500) {
        res.status(400).json({ error: 'Comment text must be 1–500 characters' });
        return;
    }
    const comment = await (0, videoRepository_1.addComment)(video.id, req.userId, text);
    if (req.userId !== video.creatorId) {
        messagingStore_1.messagingStore.createNotification({
            userId: video.creatorId,
            type: 'video_comment',
            title: 'New comment on your video',
            body: text.slice(0, 140),
            data: {
                videoId: video.id,
                commentId: comment.id,
                actorUserId: req.userId,
            },
        });
    }
    const mentionUsername = extractLeadingMentionUsername(text);
    if (mentionUsername) {
        const mentioned = await (0, userRepository_1.findUserByUsername)(mentionUsername);
        if (mentioned && mentioned.id !== req.userId && mentioned.id !== video.creatorId) {
            messagingStore_1.messagingStore.createNotification({
                userId: mentioned.id,
                type: 'comment_reply',
                title: 'New reply to your comment',
                body: text.slice(0, 140),
                data: {
                    videoId: video.id,
                    commentId: comment.id,
                    actorUserId: req.userId,
                },
            });
        }
    }
    res.status(201).json({ comment });
});
// POST /api/videos/:id/report
router.post('/:id/report', auth_1.requireAuth, async (req, res) => {
    const video = await (0, videoRepository_1.getVideoById)(req.params.id);
    if (!video)
        throw new errorHandler_1.HttpError(404, 'Video not found');
    const parsed = reportVideoSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const report = adminStore_1.adminStore.createReport({
        videoId: video.id,
        reporterUserId: req.userId,
        reason: parsed.data.reason.trim(),
        notes: parsed.data.notes?.trim() || undefined,
    });
    res.status(201).json({ report });
});
exports.default = router;
//# sourceMappingURL=videos.js.map