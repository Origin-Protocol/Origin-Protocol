"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importStar(require("express"));
const zod_1 = require("zod");
const auth_1 = require("../middleware/auth");
const featureCatalog_1 = require("../services/studio/featureCatalog");
const studioQueue_1 = require("../services/studio/studioQueue");
const creditsService_1 = require("../services/studio/creditsService");
const studioObjectStorageService_1 = require("../services/studio/studioObjectStorageService");
const plans_1 = require("../services/studio/plans");
const featureCatalog_2 = require("../services/studio/featureCatalog");
const userRepository_1 = require("../repositories/userRepository");
const studioUsageService_1 = require("../services/studio/studioUsageService");
const router = (0, express_1.Router)();
const createJobSchema = zod_1.z.object({
    feature: zod_1.z.enum([
        'trim',
        'captions',
        'filters',
        'templates',
        'auto_edit',
        'auto_caption_whisper',
        'noise_remove',
        'smart_crop',
        'thumbnail_generate',
        'text_to_video',
        'describe_to_animate',
        'ai_dialogue',
        'ai_voice_acting',
        'lip_sync',
        'character_consistency',
    ]),
    mediaKey: zod_1.z.string().min(3).optional(),
    prompt: zod_1.z.string().min(3).max(2000).optional(),
    options: zod_1.z.record(zod_1.z.unknown()).optional(),
    preferredProvider: zod_1.z.string().optional(),
});
const generateSchema = zod_1.z.object({
    prompt: zod_1.z.string().min(3).max(2000),
    tier: zod_1.z.enum(['free', 'paid']).optional(),
    options: zod_1.z.record(zod_1.z.unknown()).optional(),
});
const editSchema = zod_1.z.object({
    mediaKey: zod_1.z.string().min(3),
    editType: zod_1.z.enum(['motion', 'stylization', 're_timing']).default('motion'),
    tier: zod_1.z.enum(['free', 'paid']).optional(),
    options: zod_1.z.record(zod_1.z.unknown()).optional(),
});
const listJobsSchema = zod_1.z.object({
    status: zod_1.z.enum(['queued', 'running', 'succeeded', 'failed', 'canceled']).optional(),
});
const signUploadSchema = zod_1.z.object({
    extension: zod_1.z.string().default('mp4'),
    mimeType: zod_1.z.string().optional(),
});
async function resolveStudioTier(userId, requested) {
    if (requested === 'free')
        return 'free';
    const user = await (0, userRepository_1.findUserById)(userId);
    const hasCreatorMembership = Boolean(user?.creatorKeyId);
    if (requested === 'paid') {
        if (!hasCreatorMembership) {
            throw new Error('Paid tier requires an active creator membership.');
        }
        return 'paid';
    }
    return hasCreatorMembership ? 'paid' : 'free';
}
function toUnifiedStatus(job) {
    return {
        id: job.id,
        status: job.status,
        progress: job.progress,
        step: job.step,
        kind: job.kind,
        tier: job.tier,
        model: job.model,
        createdAt: job.createdAt,
        startedAt: job.startedAt,
        finishedAt: job.finishedAt,
        error: job.error,
        input: {
            prompt: job.input.prompt,
            mediaKey: job.input.mediaKey,
            editType: job.editType,
        },
        output: job.output,
    };
}
router.put('/uploads/local/:token', express_1.default.raw({ type: '*/*', limit: '1024mb' }), async (req, res) => {
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const result = await studioObjectStorageService_1.studioObjectStorageService.writeLocalUpload(req.params.token, body);
    res.status(201).json({ uploaded: result });
});
router.use(auth_1.requireAuth);
router.get('/features', (_req, res) => {
    res.json({
        features: featureCatalog_1.STUDIO_FEATURES,
        phases: {
            phase1: 'Basic local/client-side tools',
            phase2: 'AI assisted server-side tools',
            phase3: 'AI generation server-side tools',
        },
    });
});
router.get('/pricing', async (req, res) => {
    const tier = await resolveStudioTier(req.userId);
    const usage = studioUsageService_1.studioUsageService.getUsageSummary(req.userId, tier);
    res.json({
        plans: plans_1.STUDIO_PLAN_CATALOG,
        creditPacks: plans_1.STUDIO_CREDIT_PACKS,
        creditCosts: {
            generate: {
                cogvideox: plans_1.STUDIO_CREDIT_COSTS.cogvideox,
                hunyuan_video: plans_1.STUDIO_CREDIT_COSTS.hunyuan_video,
            },
            edit: {
                animatediff: plans_1.STUDIO_CREDIT_COSTS.animatediff,
            },
        },
        usage,
    });
});
router.get('/credits', (req, res) => {
    const credits = creditsService_1.studioCreditsService.get(req.userId);
    res.json({ credits });
});
router.post('/uploads/sign', async (req, res) => {
    const parsed = signUploadSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const target = studioObjectStorageService_1.studioObjectStorageService.createUploadTarget({
        userId: req.userId,
        extension: parsed.data.extension,
        mimeType: parsed.data.mimeType,
    });
    const upload = await studioObjectStorageService_1.studioObjectStorageService.attachSignedUploadUrl(target);
    res.json({
        upload,
    });
});
router.post('/jobs', async (req, res) => {
    const parsed = createJobSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    try {
        const mediaKey = parsed.data.mediaKey?.trim();
        if (mediaKey) {
            studioObjectStorageService_1.studioObjectStorageService.assertUserCanAccessMediaKey(req.userId, mediaKey);
        }
        const def = (0, featureCatalog_2.getFeatureDefinition)(parsed.data.feature);
        const fallbackKind = def?.kind === 'generate' ? 'generate' : 'edit';
        const tier = await resolveStudioTier(req.userId);
        const job = studioQueue_1.studioQueue.enqueue({
            userId: req.userId,
            kind: fallbackKind,
            tier,
            feature: parsed.data.feature,
            mediaKey,
            prompt: parsed.data.prompt?.trim(),
            options: parsed.data.options,
            editType: 'motion',
        });
        res.status(202).json({ job: toUnifiedStatus(job) });
    }
    catch (error) {
        res.status(422).json({ error: error.message });
    }
});
router.post('/generate', async (req, res) => {
    const parsed = generateSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    try {
        const tier = await resolveStudioTier(req.userId, parsed.data.tier);
        const job = studioQueue_1.studioQueue.enqueue({
            userId: req.userId,
            kind: 'generate',
            tier,
            feature: 'text_to_video',
            prompt: parsed.data.prompt.trim(),
            options: parsed.data.options,
        });
        res.status(202).json({ job: toUnifiedStatus(job) });
    }
    catch (error) {
        res.status(422).json({ error: error.message });
    }
});
router.post('/edit', async (req, res) => {
    const parsed = editSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    try {
        const mediaKey = parsed.data.mediaKey.trim();
        studioObjectStorageService_1.studioObjectStorageService.assertUserCanAccessMediaKey(req.userId, mediaKey);
        const tier = await resolveStudioTier(req.userId, parsed.data.tier);
        const job = studioQueue_1.studioQueue.enqueue({
            userId: req.userId,
            kind: 'edit',
            tier,
            feature: 'auto_edit',
            mediaKey,
            editType: parsed.data.editType,
            options: parsed.data.options,
        });
        res.status(202).json({ job: toUnifiedStatus(job) });
    }
    catch (error) {
        res.status(422).json({ error: error.message });
    }
});
router.get('/jobs', (req, res) => {
    const parsed = listJobsSchema.safeParse(req.query ?? {});
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const status = parsed.data.status;
    const items = studioQueue_1.studioQueue.listByUser(req.userId, status);
    res.json({ items: items.map(toUnifiedStatus) });
});
router.get('/jobs/:id', (req, res) => {
    const job = studioQueue_1.studioQueue.getById(req.params.id);
    if (!job || job.userId !== req.userId) {
        res.status(404).json({ error: 'Studio job not found' });
        return;
    }
    res.json({ job: toUnifiedStatus(job) });
});
router.get('/job/:id', (req, res) => {
    const job = studioQueue_1.studioQueue.getById(req.params.id);
    if (!job || job.userId !== req.userId) {
        res.status(404).json({ error: 'Studio job not found' });
        return;
    }
    res.json({ job: toUnifiedStatus(job) });
});
router.post('/jobs/:id/cancel', (req, res) => {
    const job = studioQueue_1.studioQueue.cancel(req.userId, req.params.id);
    if (!job) {
        res.status(404).json({ error: 'Studio job not found' });
        return;
    }
    res.json({ job: toUnifiedStatus(job) });
});
router.get('/jobs/:id/result', async (req, res) => {
    const job = studioQueue_1.studioQueue.getById(req.params.id);
    if (!job || job.userId !== req.userId) {
        res.status(404).json({ error: 'Studio job not found' });
        return;
    }
    if (job.status !== 'succeeded' || !job.output) {
        res.status(409).json({ error: 'Studio job output is not ready yet' });
        return;
    }
    const downloadUrl = await studioObjectStorageService_1.studioObjectStorageService.getDownloadUrl(req.userId, job.output.mediaKey);
    res.json({
        output: {
            ...job.output,
            downloadUrl,
        },
    });
});
exports.default = router;
//# sourceMappingURL=studio.js.map