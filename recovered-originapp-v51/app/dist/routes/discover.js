"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const recommendationService_1 = require("../services/recommendationService");
const router = (0, express_1.Router)();
function parseFeedType(value) {
    if (typeof value !== 'string')
        return 'home';
    if (value === 'community' || value === 'spotlight' || value === 'fairness')
        return value;
    return 'home';
}
function tokenize(input) {
    return input
        .toLowerCase()
        .split(/[^a-z0-9_]+/i)
        .map((token) => token.trim())
        .filter((token) => token.length >= 2)
        .slice(0, 8);
}
function normalize01(value) {
    return Math.max(0, Math.min(1, value));
}
function ageInDays(isoDate) {
    const ts = Date.parse(isoDate);
    if (Number.isNaN(ts))
        return 365;
    return Math.max(0, (Date.now() - ts) / (1000 * 60 * 60 * 24));
}
function textMatchScore(tokens, phrase, fields) {
    if (tokens.length === 0)
        return 0;
    let points = 0;
    for (const token of tokens) {
        if (fields.title.startsWith(token)) {
            points += 1.2;
            continue;
        }
        if (fields.title.includes(token)) {
            points += 1;
            continue;
        }
        if (fields.creator.includes(token)) {
            points += 0.8;
            continue;
        }
        if (fields.description.includes(token)) {
            points += 0.55;
            continue;
        }
    }
    if (phrase && fields.title.includes(phrase)) {
        points += 1.25;
    }
    else if (phrase && fields.description.includes(phrase)) {
        points += 0.75;
    }
    return normalize01(points / Math.max(2, tokens.length * 1.6));
}
// GET /api/discover/search?q=creator&page=1&pageSize=12&feedType=home
router.get('/search', auth_1.requireAuth, async (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
    const page = Math.max(1, parseInt(req.query.page ?? '1', 10));
    const pageSize = Math.min(40, Math.max(1, parseInt(req.query.pageSize ?? '12', 10)));
    const feedType = parseFeedType(req.query.feedType);
    if (!q) {
        const ranked = await recommendationService_1.recommendationService.rankFeed(req.userId, { feedType, page, pageSize });
        res.json({
            query: '',
            feedType,
            items: ranked.items,
            total: ranked.total,
            page,
            pageSize,
            hasMore: ranked.hasMore,
            ranking: {
                mode: 'healthy-feed',
                weights: {
                    textRelevance: 0,
                    recency: 0,
                    healthySignals: 1,
                    engagement: 0,
                },
            },
        });
        return;
    }
    const tokens = tokenize(q);
    const candidateSize = Math.min(800, Math.max(120, pageSize * 25));
    const ranked = await recommendationService_1.recommendationService.rankFeed(req.userId, {
        feedType,
        page: 1,
        pageSize: candidateSize,
    });
    const engagementMax = Math.max(1, ...ranked.items.map((item) => item.viewCount + item.likeCount * 4 + item.commentCount * 3));
    const withScores = ranked.items
        .map((item) => {
        const title = item.title.toLowerCase();
        const description = (item.description ?? '').toLowerCase();
        const creator = `${item.creatorDisplayName ?? ''} ${item.creatorUsername ?? ''}`.toLowerCase();
        const text = textMatchScore(tokens, q, { title, description, creator });
        const recency = Math.exp(-ageInDays(item.createdAt) / 21);
        const healthySignals = normalize01(((item.recommendation.components.health + 1) / 2) * 0.6
            + ((item.recommendation.components.provenance + 1) / 2) * 0.25
            + item.recommendation.components.equity * 0.15);
        const engagement = normalize01((item.viewCount + item.likeCount * 4 + item.commentCount * 3) / engagementMax);
        const score = text * 0.58 + recency * 0.2 + healthySignals * 0.17 + engagement * 0.05;
        const matched = text > 0.18;
        return {
            item,
            matched,
            score,
        };
    })
        .filter((row) => row.matched)
        .sort((a, b) => b.score - a.score);
    const total = withScores.length;
    const start = (page - 1) * pageSize;
    const items = withScores.slice(start, start + pageSize).map((row) => row.item);
    res.json({
        query: q,
        feedType,
        items,
        total,
        page,
        pageSize,
        hasMore: start + pageSize < total,
        ranking: {
            mode: 'blended-search',
            weights: {
                textRelevance: 0.58,
                recency: 0.2,
                healthySignals: 0.17,
                engagement: 0.05,
            },
        },
    });
});
exports.default = router;
//# sourceMappingURL=discover.js.map