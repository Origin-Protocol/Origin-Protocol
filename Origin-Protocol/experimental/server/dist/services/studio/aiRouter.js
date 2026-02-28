"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pickProvider = pickProvider;
exports.getRoutingHint = getRoutingHint;
const featureCatalog_1 = require("./featureCatalog");
function pickProvider(feature, preferredProvider) {
    const def = (0, featureCatalog_1.getFeatureDefinition)(feature);
    if (!def)
        return 'local';
    if (preferredProvider) {
        const preferred = preferredProvider;
        if (def.providers.includes(preferred)) {
            return preferred;
        }
    }
    return def.providers[0] ?? 'local';
}
function getRoutingHint(feature, provider) {
    switch (provider) {
        case 'openai':
            return `Route ${feature} job through OpenAI adapter`;
        case 'runway':
            return `Route ${feature} job through Runway adapter`;
        case 'pika':
            return `Route ${feature} job through Pika adapter`;
        case 'luma':
            return `Route ${feature} job through Luma adapter`;
        case 'elevenlabs':
            return `Route ${feature} job through ElevenLabs adapter`;
        case 'demucs':
            return `Route ${feature} job through Demucs worker`;
        case 'rnnoise':
            return `Route ${feature} job through RNNoise worker`;
        default:
            return `Route ${feature} job through local processing worker`;
    }
}
//# sourceMappingURL=aiRouter.js.map