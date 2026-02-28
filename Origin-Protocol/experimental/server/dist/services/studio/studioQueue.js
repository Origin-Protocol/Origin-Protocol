"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.studioQueue = void 0;
const crypto_1 = require("crypto");
const r2Layout_1 = require("./r2Layout");
const creditsService_1 = require("./creditsService");
const studioStore_1 = require("./studioStore");
const registry_1 = require("./adapters/registry");
const plans_1 = require("./plans");
const modelRouter_1 = require("./routing/modelRouter");
const studioObjectStorageService_1 = require("./studioObjectStorageService");
const studioUsageService_1 = require("./studioUsageService");
const recoveredJobs = studioStore_1.studioStore.getJobs();
const jobsById = new Map(recoveredJobs.map((job) => {
    const normalized = {
        ...job,
        kind: job.kind ?? 'generate',
        model: job.model ?? 'cogvideox',
        tier: job.tier ?? 'free',
        provider: job.provider ?? 'cogvideox',
        feature: job.feature ?? 'text_to_video',
        phase: job.phase ?? 'phase3',
    };
    if (normalized.status === 'running') {
        return [normalized.id, {
                ...normalized,
                status: 'queued',
                step: 'resumed-after-restart',
                progress: Math.min(normalized.progress, 70),
            }];
    }
    return [normalized.id, normalized];
}));
const queue = studioStore_1.studioStore
    .getQueue()
    .filter((jobId) => jobsById.get(jobId)?.status === 'queued');
function persistJobs() {
    studioStore_1.studioStore.setJobs([...jobsById.values()]);
}
function persistQueue() {
    studioStore_1.studioStore.setQueue([...queue]);
}
let processing = false;
function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
async function processJob(jobId) {
    const job = jobsById.get(jobId);
    if (!job || job.status !== 'queued')
        return;
    const reservedCredits = plans_1.STUDIO_CREDIT_COSTS[job.model];
    job.status = 'running';
    job.startedAt = new Date().toISOString();
    persistJobs();
    const steps = [
        { pct: 10, step: 'input-validated' },
        { pct: 28, step: 'routing-model' },
        { pct: 58, step: 'running-inference' },
        { pct: 78, step: 'uploading-output' },
        { pct: 94, step: 'writing-manifest' },
    ];
    try {
        for (const marker of steps) {
            const latest = jobsById.get(job.id);
            if (latest?.status === 'canceled') {
                creditsService_1.studioCreditsService.settle(job.userId, reservedCredits, false);
                job.finishedAt = new Date().toISOString();
                persistJobs();
                return;
            }
            job.progress = marker.pct;
            job.step = marker.step;
            persistJobs();
            await wait(280);
        }
        const adapter = registry_1.studioAdapterRegistry.get(job.model);
        const adapterResult = await adapter.run({
            userId: job.userId,
            jobId: job.id,
            kind: job.kind,
            tier: job.tier,
            model: job.model,
            prompt: job.input.prompt,
            mediaKey: job.input.mediaKey,
            editType: job.editType,
            options: job.input.options,
        });
        const outputMediaKey = r2Layout_1.studioR2Layout.outputKey({
            userId: job.userId,
            jobId: job.id,
            feature: job.feature,
            extension: adapterResult.outputExtension,
        });
        const outputManifestKey = r2Layout_1.studioR2Layout.manifestKey({
            userId: job.userId,
            jobId: job.id,
            feature: job.feature,
        });
        await studioObjectStorageService_1.studioObjectStorageService.writeObject({
            mediaKey: outputMediaKey,
            body: adapterResult.outputBuffer,
            contentType: adapterResult.outputMimeType,
        });
        const tierPlan = plans_1.STUDIO_PLAN_CATALOG[job.tier];
        const outputMetadata = {
            modelUsed: job.model,
            tierUsed: job.tier,
            durationSeconds: adapterResult.durationSeconds,
            costEstimateUsd: adapterResult.estimatedCostUsd,
            queuePriority: tierPlan.queuePriority,
            watermarked: tierPlan.watermark,
            resolution: (0, plans_1.coerceResolutionForTier)(job.tier, job.input.options?.resolution),
        };
        await studioObjectStorageService_1.studioObjectStorageService.writeJsonObject({
            mediaKey: outputManifestKey,
            payload: {
                jobId: job.id,
                userId: job.userId,
                kind: job.kind,
                model: job.model,
                tier: job.tier,
                editType: job.editType,
                input: {
                    prompt: job.input.prompt,
                    mediaKey: job.input.mediaKey,
                    options: job.input.options,
                },
                output: {
                    mediaKey: outputMediaKey,
                    metadata: outputMetadata,
                },
                trace: adapterResult.trace,
                completedAt: new Date().toISOString(),
            },
        });
        job.status = 'succeeded';
        job.progress = 100;
        job.step = 'completed';
        job.finishedAt = new Date().toISOString();
        job.output = {
            mediaKey: outputMediaKey,
            manifestKey: outputManifestKey,
            downloadUrl: `/api/studio/jobs/${job.id}/result`,
            metadata: outputMetadata,
        };
        studioUsageService_1.studioUsageService.recordSuccess(job.userId, job.kind);
        creditsService_1.studioCreditsService.settle(job.userId, reservedCredits, true);
        persistJobs();
    }
    catch (error) {
        job.status = 'failed';
        job.error = error.message || 'Studio worker failed';
        job.finishedAt = new Date().toISOString();
        creditsService_1.studioCreditsService.settle(job.userId, reservedCredits, false);
        persistJobs();
    }
}
async function processLoop() {
    if (processing)
        return;
    processing = true;
    while (queue.length > 0) {
        const next = queue.shift();
        persistQueue();
        if (!next)
            continue;
        await processJob(next);
    }
    processing = false;
}
function sortByCreatedDesc(a, b) {
    return b.createdAt.localeCompare(a.createdAt);
}
exports.studioQueue = {
    enqueue(params) {
        if (params.kind === 'generate') {
            if (!params.prompt?.trim()) {
                throw new Error('Generate jobs require a prompt.');
            }
            if (params.mediaKey) {
                throw new Error('Generate jobs accept prompt-only input.');
            }
        }
        if (params.kind === 'edit') {
            if (!params.mediaKey?.trim()) {
                throw new Error('Edit jobs require a mediaKey.');
            }
            if (params.prompt) {
                throw new Error('Edit jobs accept mediaKey-only input.');
            }
        }
        const routing = (0, modelRouter_1.routeStudioModel)({
            tier: params.tier,
            kind: params.kind,
            editType: params.editType,
        });
        const billableCredits = plans_1.STUDIO_CREDIT_COSTS[routing.model];
        studioUsageService_1.studioUsageService.assertWithinLimit(params.userId, params.tier, params.kind);
        if (!creditsService_1.studioCreditsService.canReserve(params.userId, billableCredits)) {
            throw new Error('Insufficient credits for this operation');
        }
        creditsService_1.studioCreditsService.setTier(params.userId, params.tier);
        creditsService_1.studioCreditsService.reserve(params.userId, billableCredits);
        const id = (0, crypto_1.randomUUID)();
        const inputMediaKey = params.mediaKey?.trim() || (params.kind === 'generate'
            ? r2Layout_1.studioR2Layout.inputKey({
                userId: params.userId,
                jobId: id,
                feature: params.feature ?? 'text_to_video',
                extension: 'prompt.json',
            })
            : undefined);
        const providerByModel = {
            cogvideox: 'cogvideox',
            hunyuan_video: 'hunyuan_video',
            animatediff: 'animatediff',
        };
        const provider = providerByModel[routing.model];
        const createdAt = new Date().toISOString();
        const feature = params.feature ?? (params.kind === 'edit' ? 'auto_edit' : 'text_to_video');
        const job = {
            id,
            userId: params.userId,
            kind: routing.kind,
            feature,
            phase: 'phase3',
            provider,
            model: routing.model,
            tier: routing.tier,
            editType: routing.editType,
            status: 'queued',
            progress: 0,
            step: 'queued-for-worker',
            createdAt,
            input: {
                mediaKey: inputMediaKey,
                prompt: params.prompt?.trim(),
                options: params.options,
            },
        };
        jobsById.set(id, job);
        queue.push(id);
        persistJobs();
        persistQueue();
        void processLoop();
        return job;
    },
    getById(id) {
        return jobsById.get(id) ?? null;
    },
    listByUser(userId, status) {
        const items = [...jobsById.values()].filter((item) => item.userId === userId);
        const filtered = status ? items.filter((item) => item.status === status) : items;
        return filtered.sort(sortByCreatedDesc);
    },
    cancel(userId, id) {
        const job = jobsById.get(id);
        if (!job || job.userId !== userId)
            return null;
        if (job.status === 'succeeded' || job.status === 'failed')
            return job;
        job.status = 'canceled';
        job.step = 'canceled-by-user';
        job.finishedAt = new Date().toISOString();
        persistJobs();
        const queuedIndex = queue.indexOf(id);
        if (queuedIndex >= 0) {
            queue.splice(queuedIndex, 1);
            persistQueue();
            creditsService_1.studioCreditsService.settle(job.userId, plans_1.STUDIO_CREDIT_COSTS[job.model], false);
        }
        return job;
    },
};
persistJobs();
persistQueue();
if (queue.length > 0) {
    void processLoop();
}
//# sourceMappingURL=studioQueue.js.map