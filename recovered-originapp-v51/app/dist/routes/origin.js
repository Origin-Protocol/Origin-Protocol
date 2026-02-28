"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const zod_1 = require("zod");
const auth_1 = require("../middleware/auth");
const originService_1 = require("../services/originService");
const router = (0, express_1.Router)();
const verifySchema = zod_1.z.object({
    creatorId: zod_1.z.string(),
    keyId: zod_1.z.string(),
    assetId: zod_1.z.string(),
    originId: zod_1.z.string().optional(),
    contentHash: zod_1.z.string(),
});
// POST /api/origin/verify
router.post('/verify', auth_1.requireAuth, async (req, res) => {
    const parsed = verifySchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const result = await originService_1.originService.verify(parsed.data);
    res.json(result);
});
// GET /api/origin/key-status?creatorId=&keyId=
router.get('/key-status', auth_1.requireAuth, async (req, res) => {
    const creatorId = req.query.creatorId ?? '';
    const keyId = req.query.keyId ?? '';
    if (!creatorId || !keyId) {
        res.status(400).json({ error: 'creatorId and keyId are required' });
        return;
    }
    const result = await originService_1.originService.keyStatus(creatorId, keyId);
    res.json(result);
});
exports.default = router;
//# sourceMappingURL=origin.js.map