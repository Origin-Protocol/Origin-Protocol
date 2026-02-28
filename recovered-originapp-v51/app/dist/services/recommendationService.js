"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.recommendationService = void 0;
const adminStore_1 = require("./adminStore");
const videoRepository_1 = require("../repositories/videoRepository");
const adaptiveCache = {
    multipliers: { interest: 1, community: 1, provenance: 1, health: 1, equity: 1 },
    updatedAt: 0,
};
const POSITIVE_WORDS = ['learn', 'tutorial', 'build', 'creative', 'community', 'helpful', 'education', 'guide'];
const NEGATIVE_WORDS = ['rage', 'hate', 'attack', 'harass', 'toxic', 'fraud', 'lie', 'scam'];
function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}
function normalize(value, max) {
    if (max <= 0)
        return 0;
    return clamp(value / max, 0, 1);
}
function parseBoostMeta(description) {
    if (!description)
        return false;
    return description.includes('[origin_boost]');
}
function textScore(video) {
    const text = `${video.title} ${video.description ?? ''}`.toLowerCase();
    let positive = 0;
    let negative = 0;
    for (const word of POSITIVE_WORDS) {
        if (text.includes(word))
            positive += 1;
    }
    for (const word of NEGATIVE_WORDS) {
        if (text.includes(word))
            negative += 1;
    }
    return { positive, negative };
}
function toneBucket(video) {
    const score = textScore(video);
    if (score.negative > score.positive)
        return 'negative';
    if (score.positive > 0)
        return 'positive';
    return 'neutral';
}
function pickTopKeywords(text, preferred) {
    if (preferred.length === 0)
        return 0;
    const normalizedText = text.toLowerCase();
    let matches = 0;
    for (const keyword of preferred) {
        if (normalizedText.includes(keyword))
            matches += 1;
    }
    return matches;
}
function computeAdaptiveMultipliers() {
    const cfg = adminStore_1.adminStore.getRecommendationConfig();
    if (!cfg.aiAdaptiveEnabled) {
        return { interest: 1, community: 1, provenance: 1, health: 1, equity: 1 };
    }
    const now = Date.now();
    if (now - adaptiveCache.updatedAt < 5 * 60 * 1000) {
        return adaptiveCache.multipliers;
    }
    const reports = adminStore_1.adminStore.listReports('all', 1000);
    const openRatio = reports.length > 0
        ? reports.filter((row) => row.status === 'open').length / reports.length
        : 0;
    const logs = adminStore_1.adminStore.listErrorLogs(500);
    const moderationWarnings = logs.filter((row) => row.source === 'content-moderation').length;
    // AI-assisted adaptive behavior with deterministic bounded adjustments.
    // The heuristics nudge weights automatically so operators do not micromanage daily tuning.
    const healthBoost = clamp(1 + openRatio * 0.4 + Math.min(0.2, moderationWarnings / 1000), 0.85, 1.4);
    const equityBoost = clamp(1 + openRatio * 0.2, 0.9, 1.25);
    const interestTrim = clamp(1 - openRatio * 0.2, 0.75, 1.1);
    adaptiveCache.multipliers = {
        interest: interestTrim,
        community: 1,
        provenance: 1.05,
        health: healthBoost,
        equity: equityBoost,
    };
    adaptiveCache.updatedAt = now;
    return adaptiveCache.multipliers;
}
exports.recommendationService = {
    async rankFeed(userId, opts) {
        const config = adminStore_1.adminStore.getRecommendationConfig();
        const adaptive = computeAdaptiveMultipliers();
        const feedType = opts.feedType;
        const page = Math.max(1, opts.page);
        const pageSize = clamp(opts.pageSize, 1, 100);
        const candidateSize = clamp(pageSize * 12, 120, 1200);
        const feed = await (0, videoRepository_1.listFeed)(1, candidateSize);
        const reports = adminStore_1.adminStore.listReports('all', 3000);
        const reportCountByVideo = new Map();
        for (const report of reports) {
            reportCountByVideo.set(report.videoId, (reportCountByVideo.get(report.videoId) ?? 0) + 1);
        }
        const interaction = await (0, videoRepository_1.getUserInteractionSignals)(userId);
        const creatorVideoCount = new Map();
        for (const item of feed.items) {
            creatorVideoCount.set(item.creatorId, (creatorVideoCount.get(item.creatorId) ?? 0) + 1);
        }
        const popularityMax = Math.max(1, ...feed.items.map((item) => item.viewCount + item.likeCount * 5 + item.commentCount * 4));
        const scored = feed.items
            .map((video) => {
            const reasons = [];
            const interestFromCreator = interaction.preferredCreators.includes(video.creatorId) ? 1 : 0;
            const keywordMatches = pickTopKeywords(`${video.title} ${video.description ?? ''}`, interaction.topicKeywords);
            const interestFromKeywords = normalize(keywordMatches, 8);
            const tone = toneBucket(video);
            const tonePreference = tone === 'positive' ? 0.25 : tone === 'neutral' ? 0.12 : 0;
            const interest = clamp(interestFromCreator * 0.55 + interestFromKeywords * 0.35 + tonePreference, 0, 1);
            if (interestFromCreator > 0)
                reasons.push('Matches creators you engage with');
            if (interestFromKeywords > 0.2)
                reasons.push('Matches your topic interests');
            const community = clamp((interestFromCreator > 0 ? 0.45 : 0)
                + normalize(keywordMatches, 5) * 0.35
                + (video.originBundleId ? 0.2 : 0), 0, 1);
            if (community > 0.45)
                reasons.push('Aligned with your communities');
            const hasConflict = (video.originReasons ?? []).some((r) => ['asset_id_collision', 'signature_invalid', 'fingerprint_mismatch'].includes(r.code));
            const provenance = clamp((video.originVerified ? 0.65 : 0)
                + (video.originBundleId ? 0.25 : 0)
                - (hasConflict ? 0.7 : 0), -1, 1);
            if (video.originVerified)
                reasons.push('Verified provenance');
            if (hasConflict)
                reasons.push('Downranked due to provenance conflicts');
            const contentTone = textScore(video);
            const reportPenalty = normalize(reportCountByVideo.get(video.id) ?? 0, 8);
            const health = clamp(0.35
                + normalize(contentTone.positive, 4) * 0.4
                - normalize(contentTone.negative, 4) * 0.55
                - reportPenalty * 0.5, -1, 1);
            if (health > 0.45)
                reasons.push('Healthy engagement profile');
            if (health < config.healthDownrankThreshold)
                reasons.push('Downranked by health safeguards');
            const creatorCount = creatorVideoCount.get(video.creatorId) ?? 1;
            const smallCreatorBoost = creatorCount <= 2 ? 0.7 : creatorCount <= 5 ? 0.45 : 0.15;
            const popularity = normalize(video.viewCount + video.likeCount * 5 + video.commentCount * 4, popularityMax);
            const equity = clamp(smallCreatorBoost + (1 - popularity) * 0.45, 0, 1);
            if (equity > 0.6)
                reasons.push('Creator fairness rotation boost');
            const baseWeights = {
                interest: config.weights.interest * adaptive.interest,
                community: config.weights.community * adaptive.community,
                provenance: config.weights.provenance * adaptive.provenance,
                health: config.weights.health * adaptive.health,
                equity: config.weights.equity * adaptive.equity,
            };
            let score = interest * baseWeights.interest
                + community * baseWeights.community
                + provenance * baseWeights.provenance
                + health * baseWeights.health
                + equity * baseWeights.equity;
            // Strict health/abuse suppression.
            if (health < config.healthDownrankThreshold) {
                score -= 0.8;
            }
            const boosted = parseBoostMeta(video.description);
            if (feedType === 'spotlight') {
                score = boosted ? score + config.spotlightBoostVisibility : -1000;
            }
            else {
                // Boosts never affect main recommendation ranking.
                score += 0;
            }
            if (feedType === 'community') {
                score += community * 0.35 + provenance * 0.1;
            }
            if (feedType === 'fairness') {
                score += equity * 0.6 - popularity * 0.2;
            }
            return {
                ...video,
                recommendation: {
                    feedType,
                    score: Number(score.toFixed(6)),
                    reasons: reasons.slice(0, 4),
                    components: { interest, community, provenance, health, equity },
                },
            };
        })
            .filter((video) => feedType === 'spotlight' ? video.recommendation.score > -900 : true)
            .sort((a, b) => b.recommendation.score - a.recommendation.score);
        const dominanceCap = Math.max(1, config.creatorDominanceCap);
        const fairList = [];
        const creatorShown = new Map();
        for (const item of scored) {
            if (feedType !== 'spotlight' && (creatorShown.get(item.creatorId) ?? 0) >= dominanceCap) {
                continue;
            }
            fairList.push(item);
            creatorShown.set(item.creatorId, (creatorShown.get(item.creatorId) ?? 0) + 1);
        }
        const total = fairList.length;
        const start = (page - 1) * pageSize;
        const items = fairList.slice(start, start + pageSize);
        return {
            items,
            total,
            page,
            pageSize,
            hasMore: start + pageSize < total,
        };
    },
};
//# sourceMappingURL=recommendationService.js.map