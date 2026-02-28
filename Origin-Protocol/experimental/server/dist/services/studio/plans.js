"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.STUDIO_CREDIT_COSTS = exports.STUDIO_CREDIT_PACKS = exports.STUDIO_PLAN_CATALOG = void 0;
exports.coerceResolutionForTier = coerceResolutionForTier;
exports.defaultDurationForKind = defaultDurationForKind;
// Launch plan catalog for the initial Creator AI Studio rollout.
exports.STUDIO_PLAN_CATALOG = {
    free: {
        tier: 'free',
        displayName: 'Creator Free',
        monthlyPriceUsd: 0,
        monthlyGenerateLimit: 15,
        monthlyEditLimit: 10,
        watermark: true,
        queuePriority: 'low',
        maxResolution: '720p',
        allowedGenerateModels: ['cogvideox'],
        allowedEditTypes: ['motion', 'stylization', 're_timing'],
    },
    paid: {
        tier: 'paid',
        displayName: 'Creator Pro',
        monthlyPriceUsd: 19,
        monthlyGenerateLimit: 'unlimited',
        monthlyEditLimit: 'unlimited',
        watermark: false,
        queuePriority: 'high',
        maxResolution: '4k',
        allowedGenerateModels: ['hunyuan_video', 'cogvideox'],
        allowedEditTypes: ['motion', 'stylization', 're_timing'],
    },
};
exports.STUDIO_CREDIT_PACKS = [
    { usd: 5, credits: 50 },
    { usd: 10, credits: 120 },
    { usd: 20, credits: 300 },
];
exports.STUDIO_CREDIT_COSTS = {
    cogvideox: 1,
    hunyuan_video: 4,
    animatediff: 1,
};
function coerceResolutionForTier(tier, requested) {
    const normalized = String(requested ?? '').toLowerCase();
    if (tier === 'free')
        return '720p';
    if (normalized === '4k')
        return '4k';
    if (normalized === '1080p')
        return '1080p';
    return '1080p';
}
function defaultDurationForKind(kind) {
    return kind === 'edit' ? 6 : 8;
}
//# sourceMappingURL=plans.js.map