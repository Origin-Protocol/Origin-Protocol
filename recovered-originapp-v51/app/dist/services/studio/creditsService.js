"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.studioCreditsService = void 0;
const studioStore_1 = require("./studioStore");
const initialCredits = studioStore_1.studioStore.getCreditsRecord();
const creditMap = new Map(Object.entries(initialCredits));
function persistCredits() {
    studioStore_1.studioStore.setCreditsRecord(Object.fromEntries(creditMap.entries()));
}
function defaultCredits(tier = 'free') {
    const monthlyLimit = tier === 'paid' ? 6000 : 40;
    return {
        tier,
        remaining: monthlyLimit,
        reserved: 0,
        monthlyLimit,
    };
}
exports.studioCreditsService = {
    get(userId) {
        const existing = creditMap.get(userId);
        if (existing)
            return existing;
        const created = defaultCredits('free');
        creditMap.set(userId, created);
        persistCredits();
        return created;
    },
    setTier(userId, tier) {
        const credits = this.get(userId);
        if (credits.tier === tier)
            return credits;
        const next = defaultCredits(tier);
        credits.tier = next.tier;
        credits.monthlyLimit = next.monthlyLimit;
        credits.remaining = Math.min(credits.remaining, next.monthlyLimit);
        persistCredits();
        return credits;
    },
    canReserve(userId, amount) {
        const credits = this.get(userId);
        return credits.remaining >= amount;
    },
    reserve(userId, amount) {
        const credits = this.get(userId);
        credits.remaining = Math.max(0, credits.remaining - amount);
        credits.reserved += amount;
        persistCredits();
    },
    settle(userId, amount, succeeded) {
        const credits = this.get(userId);
        credits.reserved = Math.max(0, credits.reserved - amount);
        if (!succeeded) {
            credits.remaining += amount;
        }
        persistCredits();
    },
    addCredits(userId, amount) {
        const credits = this.get(userId);
        credits.remaining = Math.max(0, credits.remaining + Math.max(0, amount));
        persistCredits();
        return credits;
    },
};
//# sourceMappingURL=creditsService.js.map