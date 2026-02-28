"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const recommendationService_1 = require("../services/recommendationService");
const router = (0, express_1.Router)();
const DEFAULT_PAGE_SIZE = 20;
function parseFeedType(value) {
    if (typeof value !== 'string')
        return 'home';
    if (value === 'community' || value === 'spotlight' || value === 'fairness')
        return value;
    return 'home';
}
// GET /api/feed?page=1&pageSize=20
router.get('/', auth_1.requireAuth, async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page ?? '1', 10));
    const pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize ?? String(DEFAULT_PAGE_SIZE), 10)));
    const feedType = parseFeedType(req.query.feedType);
    const { items, total, hasMore } = await recommendationService_1.recommendationService.rankFeed(req.userId, {
        feedType,
        page,
        pageSize,
    });
    res.json({
        feedType,
        items,
        total,
        page,
        pageSize,
        hasMore,
    });
});
exports.default = router;
//# sourceMappingURL=feed.js.map