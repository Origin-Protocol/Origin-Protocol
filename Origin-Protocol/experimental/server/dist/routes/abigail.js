"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const errorHandler_1 = require("../middleware/errorHandler");
const config_1 = require("../config");
const abigailMemoryStore_1 = require("../services/abigailMemoryStore");
const router = (0, express_1.Router)();
function getTenantId(req) {
    const tenantHeader = req.headers['x-tenant-id'];
    const tenant = typeof tenantHeader === 'string' ? tenantHeader.trim() : '';
    if (!tenant) {
        throw new errorHandler_1.HttpError(422, 'Missing required header: x-tenant-id');
    }
    if (tenant !== config_1.config.abigail.tenantId) {
        throw new errorHandler_1.HttpError(403, `Tenant not allowed: ${tenant}`);
    }
    return tenant;
}
function assertApiKey(req) {
    if (!config_1.config.abigail.apiKey)
        return;
    const keyHeader = req.headers['x-api-key'];
    const key = typeof keyHeader === 'string' ? keyHeader.trim() : '';
    if (!key) {
        throw new errorHandler_1.HttpError(401, 'Missing required header: x-api-key');
    }
    if (key !== config_1.config.abigail.apiKey) {
        throw new errorHandler_1.HttpError(403, 'Invalid x-api-key');
    }
}
function parseUserId(value) {
    const userId = typeof value === 'string' ? value.trim() : '';
    if (!userId) {
        throw new errorHandler_1.HttpError(422, 'Missing required field: user_id');
    }
    return userId;
}
function parseMessage(value) {
    const message = typeof value === 'string' ? value.trim() : '';
    if (!message) {
        throw new errorHandler_1.HttpError(422, 'Missing required field: message');
    }
    return message;
}
function parseMemoryType(value) {
    const normalized = typeof value === 'string' ? value.trim().toLowerCase() : '';
    if (!normalized)
        return undefined;
    if (normalized === 'trait' || normalized === 'preference' || normalized === 'goal' || normalized === 'habit' || normalized === 'fact' || normalized === 'reaction') {
        return normalized;
    }
    return undefined;
}
function parseMemorySource(value) {
    const normalized = typeof value === 'string' ? value.trim().toLowerCase() : '';
    if (!normalized)
        return undefined;
    if (normalized === 'chat' || normalized === 'memory_patch' || normalized === 'system' || normalized === 'manual' || normalized === 'import') {
        return normalized;
    }
    return undefined;
}
function parseLimit(value, fallback, max = 50) {
    const asString = typeof value === 'string' ? value : '';
    const parsed = Number.parseInt(asString, 10);
    if (!Number.isFinite(parsed) || parsed <= 0)
        return fallback;
    return Math.min(parsed, max);
}
function buildPersonalizedReply(message, context) {
    const lower = message.toLowerCase();
    const tone = context.profile?.preferredTone || 'friendly';
    const pacing = context.profile?.pacing || 'balanced';
    const goalHint = context.profile?.goals?.[0];
    const memoryHint = context.memories[0]?.summary;
    if (/hello|hi|hey/.test(lower)) {
        return `Hi — I remember your style is ${tone} (${pacing} pacing). ${goalHint ? `Current focus: ${goalHint}.` : 'Tell me one goal you want to prioritize today.'}`;
    }
    if (/plan|schedule|roadmap|next/.test(lower)) {
        return `Here’s a personalized next step: ${goalHint ? `advance “${goalHint}” with one concrete milestone.` : 'set a single measurable goal for this week.'} ${memoryHint ? `I’m also factoring in: ${memoryHint}.` : ''}`;
    }
    return `${tone === 'direct' ? 'Direct answer:' : 'Got it.'} I’ll respond with ${pacing} detail and keep your priorities in view.${goalHint ? ` Main goal: ${goalHint}.` : ''}${memoryHint ? ` Relevant memory: ${memoryHint}.` : ''}`;
}
router.get('/abigail/healthz', (_req, res) => {
    res.json({ status: 'ok', service: 'abigail-memory', ts: new Date().toISOString() });
});
router.post('/chat', (req, res) => {
    assertApiKey(req);
    const tenantId = getTenantId(req);
    const body = req.body;
    const userId = parseUserId(body.user_id);
    const message = parseMessage(body.message);
    const ingest = abigailMemoryStore_1.abigailMemoryStore.ingestConversationTurn({
        userId,
        tenantId,
        message,
        source: 'chat',
        metadata: typeof body.metadata === 'object' && body.metadata ? body.metadata : undefined,
    });
    const context = abigailMemoryStore_1.abigailMemoryStore.retrieveContext({
        userId,
        tenantId,
        query: message,
        limit: 10,
    });
    const reply = buildPersonalizedReply(message, context);
    res.json({
        reply,
        session_id: typeof body.session_id === 'string' ? body.session_id : undefined,
        memory_updates: {
            created: ingest.created.map((item) => item.id),
            updated: ingest.updated.map((item) => item.id),
            skipped: ingest.skipped.length,
        },
        context_bundle: context.generatedContext,
    });
});
router.post('/memory/update', (req, res) => {
    assertApiKey(req);
    const tenantId = getTenantId(req);
    const body = req.body;
    const userId = parseUserId(body.user_id);
    const memoryPatch = (typeof body.memory_patch === 'object' && body.memory_patch)
        ? body.memory_patch
        : {};
    const result = abigailMemoryStore_1.abigailMemoryStore.applyMemoryPatch({
        userId,
        tenantId,
        patch: memoryPatch,
    });
    res.json({
        ok: true,
        created: result.created.length,
        updated: result.updated.length,
        events_added: result.eventsAdded,
        profile: result.profile,
    });
});
router.get('/memory/snapshot', (req, res) => {
    assertApiKey(req);
    const tenantId = getTenantId(req);
    const userId = parseUserId(req.query.user_id);
    const limit = parseLimit(req.query.limit, 80, 200);
    const snapshot = abigailMemoryStore_1.abigailMemoryStore.listSnapshot({ userId, tenantId, limit });
    res.json(snapshot);
});
router.get('/recommendations', (req, res) => {
    assertApiKey(req);
    const tenantId = getTenantId(req);
    const userId = parseUserId(req.query.user_id);
    const recommendations = abigailMemoryStore_1.abigailMemoryStore.generateRecommendations({ userId, tenantId });
    res.json({
        items: recommendations,
        recommendations,
    });
});
router.post('/memory/ingest', (req, res) => {
    assertApiKey(req);
    const tenantId = getTenantId(req);
    const body = req.body;
    const userId = parseUserId(body.user_id);
    const turns = Array.isArray(body.turns) ? body.turns : [];
    if (turns.length === 0) {
        throw new errorHandler_1.HttpError(422, 'Missing required field: turns[]');
    }
    const createdIds = [];
    const updatedIds = [];
    let skipped = 0;
    for (const turn of turns) {
        const message = parseMessage(turn.message);
        const source = parseMemorySource(turn.source) ?? 'chat';
        const ingest = abigailMemoryStore_1.abigailMemoryStore.ingestConversationTurn({
            userId,
            tenantId,
            message,
            source,
            metadata: typeof turn.metadata === 'object' && turn.metadata
                ? turn.metadata
                : undefined,
        });
        createdIds.push(...ingest.created.map((item) => item.id));
        updatedIds.push(...ingest.updated.map((item) => item.id));
        skipped += ingest.skipped.length;
    }
    res.json({
        created: createdIds,
        updated: updatedIds,
        skipped,
    });
});
router.get('/memory/context', (req, res) => {
    assertApiKey(req);
    const tenantId = getTenantId(req);
    const userId = parseUserId(req.query.user_id);
    const query = typeof req.query.query === 'string' ? req.query.query : undefined;
    const limit = parseLimit(req.query.limit, 12, 50);
    const context = abigailMemoryStore_1.abigailMemoryStore.retrieveContext({
        userId,
        tenantId,
        query,
        limit,
    });
    res.json({
        profile: context.profile,
        memories: context.memories,
        bundle: context.generatedContext,
    });
});
router.post('/memory/forget', (req, res) => {
    assertApiKey(req);
    const tenantId = getTenantId(req);
    const body = req.body;
    const userId = parseUserId(body.user_id);
    const result = abigailMemoryStore_1.abigailMemoryStore.forgetUserData({
        userId,
        tenantId,
        options: {
            type: parseMemoryType(body.type),
            source: parseMemorySource(body.source),
            beforeTs: typeof body.before_ts === 'string' ? body.before_ts : undefined,
            anonymize: Boolean(body.anonymize),
            hardDelete: Boolean(body.hard_delete),
        },
    });
    res.json({ ok: true, ...result });
});
router.get('/memory/export', (req, res) => {
    assertApiKey(req);
    const tenantId = getTenantId(req);
    const userId = parseUserId(req.query.user_id);
    const exported = abigailMemoryStore_1.abigailMemoryStore.exportUserData({ userId, tenantId });
    res.json(exported);
});
exports.default = router;
//# sourceMappingURL=abigail.js.map