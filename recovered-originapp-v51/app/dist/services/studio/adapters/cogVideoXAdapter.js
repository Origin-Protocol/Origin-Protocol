"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CogVideoXAdapter = void 0;
const config_1 = require("../../../config");
const inferenceGateway_1 = require("./inferenceGateway");
function resolveDurationSeconds(input) {
    const raw = input.options?.durationSeconds;
    const parsed = typeof raw === 'number' ? raw : Number(raw);
    return Number.isFinite(parsed) && parsed > 0 ? Math.min(12, Math.round(parsed)) : 6;
}
class CogVideoXAdapter {
    constructor() {
        this.model = 'cogvideox';
    }
    async run(input) {
        const startedAt = Date.now();
        const durationSeconds = resolveDurationSeconds(input);
        const remote = await (0, inferenceGateway_1.runRemoteStudioInference)({
            endpoint: config_1.config.studio.workers.cogVideoXUrl,
            adapterName: 'CogVideoXAdapter',
            payload: {
                model: this.model,
                prompt: input.prompt ?? '',
                durationSeconds,
                resolution: '720p',
                watermark: true,
                options: input.options ?? {},
            },
            fallbackDurationSeconds: durationSeconds,
            fallbackCostUsd: 0.015,
        });
        if (remote)
            return remote;
        // Scaffold implementation:
        // - Real inference worker call can be dropped in here later.
        // - Current payload ensures queue/storage/status integration is production-safe.
        const payload = {
            model: this.model,
            prompt: input.prompt ?? '',
            durationSeconds,
            resolution: '720p',
            watermark: true,
            note: 'Scaffold output from CogVideoX adapter',
        };
        return {
            outputBuffer: Buffer.from(JSON.stringify(payload, null, 2), 'utf8'),
            outputMimeType: 'application/json',
            outputExtension: 'json',
            durationSeconds,
            estimatedCostUsd: 0.015,
            trace: {
                adapter: 'CogVideoXAdapter',
                inferenceMs: Date.now() - startedAt,
                notes: ['free-tier text-to-video path', 'replace scaffold payload with real rendered video bytes'],
            },
        };
    }
}
exports.CogVideoXAdapter = CogVideoXAdapter;
//# sourceMappingURL=cogVideoXAdapter.js.map