"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.studioUsageService = void 0;
const plans_1 = require("./plans");
const studioStore_1 = require("./studioStore");
const usageMap = new Map(Object.entries(studioStore_1.studioStore.getUsageRecord()));
function persistUsage() {
    studioStore_1.studioStore.setUsageRecord(Object.fromEntries(usageMap.entries()));
}
function monthKey(date = new Date()) {
    return date.toISOString().slice(0, 7);
}
function buildUsageKey(userId, key) {
    return `${userId}:${key}`;
}
function getOrCreateUsage(userId, key = monthKey()) {
    const usageKey = buildUsageKey(userId, key);
    const existing = usageMap.get(usageKey);
    if (existing)
        return existing;
    const created = { generate: 0, edit: 0 };
    usageMap.set(usageKey, created);
    persistUsage();
    return created;
}
function computeRemaining(limit, used) {
    if (limit === 'unlimited')
        return 'unlimited';
    return Math.max(0, limit - used);
}
exports.studioUsageService = {
    monthKey,
    getUsage(userId, key = monthKey()) {
        const usage = getOrCreateUsage(userId, key);
        return { ...usage };
    },
    getUsageSummary(userId, tier, key = monthKey()) {
        const usage = this.getUsage(userId, key);
        const plan = plans_1.STUDIO_PLAN_CATALOG[tier];
        return {
            monthKey: key,
            tier,
            usage,
            limits: {
                generate: plan.monthlyGenerateLimit,
                edit: plan.monthlyEditLimit,
            },
            remaining: {
                generate: computeRemaining(plan.monthlyGenerateLimit, usage.generate),
                edit: computeRemaining(plan.monthlyEditLimit, usage.edit),
            },
        };
    },
    assertWithinLimit(userId, tier, kind) {
        if (tier !== 'free')
            return;
        const usage = getOrCreateUsage(userId);
        const plan = plans_1.STUDIO_PLAN_CATALOG[tier];
        const used = kind === 'generate' ? usage.generate : usage.edit;
        const limit = kind === 'generate' ? plan.monthlyGenerateLimit : plan.monthlyEditLimit;
        if (limit === 'unlimited')
            return;
        if (used >= limit) {
            const label = kind === 'generate' ? 'generation' : 'edit';
            throw new Error(`Monthly free-tier ${label} limit reached (${limit}). Upgrade to paid tier for unlimited access.`);
        }
    },
    recordSuccess(userId, kind) {
        const usage = getOrCreateUsage(userId);
        if (kind === 'generate') {
            usage.generate += 1;
        }
        else {
            usage.edit += 1;
        }
        persistUsage();
    },
};
//# sourceMappingURL=studioUsageService.js.map