"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnimateDiffAdapter = void 0;
const config_1 = require("../../../config");
const inferenceGateway_1 = require("./inferenceGateway");
function resolveDurationSeconds(input) {
    const raw = input.options?.durationSeconds;
    const parsed = typeof raw === 'number' ? raw : Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? Math.min(20, Math.round(parsed)) : 6;
}
class AnimateDiffAdapter {
    constructor() {
        this.model = 'animatediff';
    }
    async run(input) {
        const startedAt = Date.now();
        const durationSeconds = resolveDurationSeconds(input);
        const editType = input.editType ?? 'motion';
        const remote = await (0, inferenceGateway_1.runRemoteStudioInference)({
            endpoint: config_1.config.studio.workers.animateDiffUrl,
            adapterName: 'AnimateDiffAdapter',
            payload: {
                model: this.model,
                mediaKey: input.mediaKey,
                editType,
                prompt: input.prompt ?? '',
                durationSeconds,
                options: input.options ?? {},
            },
            fallbackDurationSeconds: durationSeconds,
            fallbackCostUsd: 0.01,
        });
        if (remote)
            return remote;
        const payload = {
            model: this.model,
            mediaKey: input.mediaKey,
            editType,
            prompt: input.prompt ?? '',
            durationSeconds,
            note: 'Scaffold output from AnimateDiff adapter',
        };
        return {
            outputBuffer: Buffer.from(JSON.stringify(payload, null, 2), 'utf8'),
            outputMimeType: 'application/json',
            outputExtension: 'json',
            durationSeconds,
            estimatedCostUsd: 0.01,
            trace: {
                adapter: 'AnimateDiffAdapter',
                inferenceMs: Date.now() - startedAt,
                notes: ['editing model path (motion/stylization/re_timing)', 'replace scaffold payload with real rendered video bytes'],
            },
        };
    }
}
exports.AnimateDiffAdapter = AnimateDiffAdapter;
//# sourceMappingURL=animateDiffAdapter.js.map