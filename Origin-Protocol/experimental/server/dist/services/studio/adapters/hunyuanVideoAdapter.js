"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HunyuanVideoAdapter = void 0;
const config_1 = require("../../../config");
const inferenceGateway_1 = require("./inferenceGateway");
function resolveDurationSeconds(input) {
    const raw = input.options?.durationSeconds;
    const parsed = typeof raw === 'number' ? raw : Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? Math.min(20, Math.round(parsed)) : 8;
}
class HunyuanVideoAdapter {
    constructor() {
        this.model = 'hunyuan_video';
    }
    async run(input) {
        const startedAt = Date.now();
        const durationSeconds = resolveDurationSeconds(input);
        const resolution = input.options?.resolution ?? '1080p';
        const remote = await (0, inferenceGateway_1.runRemoteStudioInference)({
            endpoint: config_1.config.studio.workers.hunyuanVideoUrl,
            adapterName: 'HunyuanVideoAdapter',
            payload: {
                model: this.model,
                prompt: input.prompt ?? '',
                durationSeconds,
                resolution,
                watermark: false,
                options: input.options ?? {},
            },
            fallbackDurationSeconds: durationSeconds,
            fallbackCostUsd: 0.12,
        });
        if (remote)
            return remote;
        const payload = {
            model: this.model,
            prompt: input.prompt ?? '',
            durationSeconds,
            resolution,
            watermark: false,
            note: 'Scaffold output from Hunyuan Video adapter',
        };
        return {
            outputBuffer: Buffer.from(JSON.stringify(payload, null, 2), 'utf8'),
            outputMimeType: 'application/json',
            outputExtension: 'json',
            durationSeconds,
            estimatedCostUsd: 0.12,
            trace: {
                adapter: 'HunyuanVideoAdapter',
                inferenceMs: Date.now() - startedAt,
                notes: ['paid-tier premium generation path', 'replace scaffold payload with real rendered video bytes'],
            },
        };
    }
}
exports.HunyuanVideoAdapter = HunyuanVideoAdapter;
//# sourceMappingURL=hunyuanVideoAdapter.js.map