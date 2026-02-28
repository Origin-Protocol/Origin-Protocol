"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.abigailMemoryStore = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const crypto_1 = __importDefault(require("crypto"));
const config_1 = require("../config");
const DATA_DIR = path_1.default.resolve('.data');
const STORE_FILE = path_1.default.join(DATA_DIR, 'abigail-memory.json');
function nowIso() {
    return new Date().toISOString();
}
function id(prefix) {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}
function clamp01(value) {
    return Math.max(0, Math.min(1, value));
}
function normalizeText(value) {
    return (value ?? '').trim().replace(/\s+/g, ' ');
}
function normalizeLower(value) {
    return normalizeText(value).toLowerCase();
}
function ensureDataDir() {
    if (!fs_1.default.existsSync(DATA_DIR)) {
        fs_1.default.mkdirSync(DATA_DIR, { recursive: true });
    }
}
function load() {
    try {
        if (!fs_1.default.existsSync(STORE_FILE)) {
            return { profiles: [], memories: [], events: [] };
        }
        const raw = fs_1.default.readFileSync(STORE_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return {
            profiles: Array.isArray(parsed.profiles) ? parsed.profiles : [],
            memories: Array.isArray(parsed.memories) ? parsed.memories : [],
            events: Array.isArray(parsed.events) ? parsed.events : [],
        };
    }
    catch {
        return { profiles: [], memories: [], events: [] };
    }
}
function persist(store) {
    ensureDataDir();
    fs_1.default.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2), 'utf8');
}
function daysSince(ts) {
    const delta = Date.now() - Date.parse(ts);
    if (!Number.isFinite(delta) || delta < 0)
        return 0;
    return delta / (24 * 60 * 60 * 1000);
}
function tokenSet(text) {
    return new Set(normalizeLower(text)
        .split(/[^a-z0-9]+/i)
        .map((item) => item.trim())
        .filter((item) => item.length >= 3));
}
class AbigailMemoryStore {
    constructor() {
        const loaded = load();
        this.profiles = loaded.profiles;
        this.memories = loaded.memories;
        this.events = loaded.events;
        this.applyRetentionPolicy();
        this.flush();
    }
    flush() {
        persist({
            profiles: this.profiles,
            memories: this.memories,
            events: this.events,
        });
    }
    isSensitive(text) {
        const hay = normalizeLower(text);
        if (!hay)
            return false;
        return config_1.config.abigail.blockedSensitiveKeywords.some((keyword) => hay.includes(keyword));
    }
    isExpired(memory) {
        if (!memory.expiresAt)
            return false;
        const expiryTs = Date.parse(memory.expiresAt);
        if (!Number.isFinite(expiryTs))
            return false;
        return expiryTs <= Date.now();
    }
    isActiveMemory(memory) {
        return !memory.softDeletedAt && !memory.hardDeletedAt && !this.isExpired(memory);
    }
    isActiveEvent(event) {
        return !event.softDeletedAt && !event.hardDeletedAt;
    }
    getOrCreateProfile(userId, tenantId) {
        let existing = this.profiles.find((profile) => profile.userId === userId && profile.tenantId === tenantId && !profile.deletedAt);
        if (existing)
            return existing;
        existing = {
            userId,
            tenantId,
            topics: [],
            goals: [],
            traits: [],
            updatedAt: nowIso(),
            deletedAt: null,
        };
        this.profiles.push(existing);
        return existing;
    }
    updateProfileFromCandidate(profile, candidate) {
        const value = normalizeText(candidate.value);
        if (!value)
            return;
        if (candidate.type === 'goal') {
            if (!profile.goals.some((item) => normalizeLower(item) === normalizeLower(value))) {
                profile.goals = [...profile.goals, value].slice(-12);
            }
        }
        if (candidate.type === 'trait') {
            if (!profile.traits.some((item) => normalizeLower(item) === normalizeLower(value))) {
                profile.traits = [...profile.traits, value].slice(-12);
            }
        }
        if (candidate.type === 'preference') {
            if (!profile.topics.some((item) => normalizeLower(item) === normalizeLower(value))) {
                profile.topics = [...profile.topics, value].slice(-20);
            }
        }
        const lower = normalizeLower(value);
        if (lower.includes('brief'))
            profile.pacing = 'brief';
        if (lower.includes('detailed') || lower.includes('deep'))
            profile.pacing = 'detailed';
        if (lower.includes('friendly') || lower.includes('formal') || lower.includes('direct')) {
            profile.preferredTone = value;
        }
        profile.updatedAt = nowIso();
    }
    rankCandidateImportance(text, base = 0.4) {
        let score = base;
        const lower = normalizeLower(text);
        if (/(always|never|must|important|priority|critical|goal)/i.test(lower))
            score += 0.25;
        if (/(prefer|like|dislike|hate|love)/i.test(lower))
            score += 0.15;
        if (/(today|this week|deadline|tomorrow)/i.test(lower))
            score += 0.1;
        return clamp01(score);
    }
    extractCandidatesFromTurn(message) {
        const text = normalizeText(message);
        if (!text)
            return [];
        const lower = normalizeLower(text);
        const candidates = [];
        const prefMatch = lower.match(/(?:i\s+(?:really\s+)?)?(?:prefer|like|love)\s+([^\.\!\?]{2,120})/i);
        if (prefMatch?.[1]) {
            const value = normalizeText(prefMatch[1]);
            candidates.push({
                type: 'preference',
                key: 'stated_preference',
                value,
                summary: `User preference: ${value}`,
                importance: this.rankCandidateImportance(text, 0.45),
                source: 'chat',
                confidence: 0.72,
                tags: ['preference'],
                decayPerDay: 0.003,
            });
        }
        const goalMatch = lower.match(/(?:my\s+goal\s+is|i\s+want\s+to|i\s+am\s+working\s+on)\s+([^\.\!\?]{2,140})/i);
        if (goalMatch?.[1]) {
            const value = normalizeText(goalMatch[1]);
            candidates.push({
                type: 'goal',
                key: 'active_goal',
                value,
                summary: `Current goal: ${value}`,
                importance: this.rankCandidateImportance(text, 0.62),
                source: 'chat',
                confidence: 0.78,
                tags: ['goal', 'actionable'],
                decayPerDay: 0.002,
            });
        }
        const habitMatch = lower.match(/(?:i\s+(?:usually|often|tend\s+to))\s+([^\.\!\?]{2,120})/i);
        if (habitMatch?.[1]) {
            const value = normalizeText(habitMatch[1]);
            candidates.push({
                type: 'habit',
                key: 'habit_pattern',
                value,
                summary: `Habit pattern: ${value}`,
                importance: this.rankCandidateImportance(text, 0.5),
                source: 'chat',
                confidence: 0.69,
                tags: ['habit'],
                decayPerDay: 0.004,
            });
        }
        const traitMatch = lower.match(/(?:i\s+am|i'm)\s+([^\.\!\?]{2,80})/i);
        if (traitMatch?.[1]) {
            const value = normalizeText(traitMatch[1]);
            if (/organized|anxious|introvert|extrovert|focused|distracted|planner|creative|direct|empathetic/i.test(value)) {
                candidates.push({
                    type: 'trait',
                    key: 'self_trait',
                    value,
                    summary: `Self-described trait: ${value}`,
                    importance: this.rankCandidateImportance(text, 0.48),
                    source: 'chat',
                    confidence: 0.64,
                    tags: ['personality'],
                    decayPerDay: 0.001,
                });
            }
        }
        if (/(frustrated|stressed|excited|overwhelmed|confident)/i.test(lower)) {
            const value = normalizeText(text.slice(0, 140));
            candidates.push({
                type: 'reaction',
                key: 'emotional_signal',
                value,
                summary: `Emotional signal: ${value}`,
                importance: this.rankCandidateImportance(text, 0.52),
                source: 'chat',
                confidence: 0.58,
                tags: ['signal'],
                decayPerDay: 0.01,
                expiresAt: new Date(Date.now() + 45 * 24 * 60 * 60 * 1000).toISOString(),
            });
        }
        return candidates;
    }
    upsertMemory(userId, tenantId, candidate) {
        const currentTs = nowIso();
        const keyNorm = normalizeLower(candidate.key);
        const valueNorm = normalizeLower(candidate.value);
        const existing = this.memories.find((record) => (record.userId === userId
            && record.tenantId === tenantId
            && !record.hardDeletedAt
            && normalizeLower(record.key) === keyNorm
            && normalizeLower(record.value) === valueNorm));
        if (existing) {
            existing.summary = candidate.summary;
            existing.importance = clamp01(Math.max(existing.importance, candidate.importance));
            existing.confidence = clamp01(Math.max(existing.confidence, candidate.confidence ?? existing.confidence));
            existing.updatedAt = currentTs;
            existing.lastObservedAt = currentTs;
            existing.source = candidate.source;
            existing.tags = [...new Set([...(existing.tags ?? []), ...(candidate.tags ?? [])])];
            if (candidate.expiresAt !== undefined) {
                existing.expiresAt = candidate.expiresAt;
            }
            if (candidate.decayPerDay !== undefined) {
                existing.decayPerDay = Math.max(0.0001, candidate.decayPerDay);
            }
            existing.softDeletedAt = null;
            return existing;
        }
        const created = {
            id: id('mem'),
            userId,
            tenantId,
            type: candidate.type,
            key: candidate.key,
            value: candidate.value,
            summary: candidate.summary,
            importance: clamp01(candidate.importance),
            confidence: clamp01(candidate.confidence ?? 0.65),
            source: candidate.source,
            tags: [...new Set(candidate.tags ?? [])],
            createdAt: currentTs,
            updatedAt: currentTs,
            lastObservedAt: currentTs,
            expiresAt: candidate.expiresAt,
            decayPerDay: Math.max(0.0001, candidate.decayPerDay ?? 0.004),
            softDeletedAt: null,
            hardDeletedAt: null,
        };
        this.memories.push(created);
        return created;
    }
    applyRetentionPolicy() {
        const now = Date.now();
        const maxRetentionMs = config_1.config.abigail.maxRetentionDays * 24 * 60 * 60 * 1000;
        const hardDeleteGraceMs = config_1.config.abigail.hardDeleteGraceDays * 24 * 60 * 60 * 1000;
        for (const memory of this.memories) {
            if (memory.hardDeletedAt)
                continue;
            const createdTs = Date.parse(memory.createdAt);
            if (Number.isFinite(createdTs) && now - createdTs > maxRetentionMs && !memory.softDeletedAt) {
                memory.softDeletedAt = nowIso();
            }
            if (memory.softDeletedAt) {
                const deletedTs = Date.parse(memory.softDeletedAt);
                if (Number.isFinite(deletedTs) && now - deletedTs > hardDeleteGraceMs) {
                    memory.hardDeletedAt = nowIso();
                }
            }
        }
        for (const event of this.events) {
            if (event.hardDeletedAt)
                continue;
            const createdTs = Date.parse(event.createdAt);
            if (Number.isFinite(createdTs) && now - createdTs > maxRetentionMs && !event.softDeletedAt) {
                event.softDeletedAt = nowIso();
            }
            if (event.softDeletedAt) {
                const deletedTs = Date.parse(event.softDeletedAt);
                if (Number.isFinite(deletedTs) && now - deletedTs > hardDeleteGraceMs) {
                    event.hardDeletedAt = nowIso();
                }
            }
        }
    }
    ingestConversationTurn(input) {
        this.applyRetentionPolicy();
        const profile = this.getOrCreateProfile(input.userId, input.tenantId);
        const candidates = this.extractCandidatesFromTurn(input.message).map((candidate) => ({
            ...candidate,
            source: input.source ?? 'chat',
        }));
        const created = [];
        const updated = [];
        const skipped = [];
        for (const candidate of candidates) {
            if (candidate.importance < config_1.config.abigail.minImportanceToStore) {
                skipped.push({ reason: 'importance_below_threshold', candidate });
                continue;
            }
            const sensitiveBlob = `${candidate.key} ${candidate.value} ${candidate.summary}`;
            if (this.isSensitive(sensitiveBlob)) {
                skipped.push({ reason: 'blocked_sensitive_category', candidate });
                continue;
            }
            const saved = this.upsertMemory(input.userId, input.tenantId, candidate);
            const wasNew = Date.parse(saved.createdAt) === Date.parse(saved.updatedAt);
            if (wasNew)
                created.push(saved);
            else
                updated.push(saved);
            this.updateProfileFromCandidate(profile, candidate);
        }
        this.events.push({
            id: id('evt'),
            userId: input.userId,
            tenantId: input.tenantId,
            eventType: 'conversation_turn',
            title: 'Conversation turn processed',
            detail: normalizeText(input.message).slice(0, 240),
            importance: clamp01(0.45 + Math.min(0.2, candidates.length * 0.05)),
            source: input.source ?? 'chat',
            createdAt: nowIso(),
            softDeletedAt: null,
            hardDeletedAt: null,
        });
        profile.updatedAt = nowIso();
        this.flush();
        return { created, updated, skipped, profile };
    }
    applyMemoryPatch(input) {
        this.applyRetentionPolicy();
        const profile = this.getOrCreateProfile(input.userId, input.tenantId);
        const created = [];
        const updated = [];
        let eventsAdded = 0;
        const patchProfile = input.patch.profile_settings;
        if (patchProfile) {
            if (patchProfile.preferred_tone)
                profile.preferredTone = normalizeText(patchProfile.preferred_tone);
            if (patchProfile.pacing)
                profile.pacing = patchProfile.pacing;
            if (Array.isArray(patchProfile.topics)) {
                profile.topics = [...new Set([...profile.topics, ...patchProfile.topics.map((item) => normalizeText(item)).filter(Boolean)])].slice(-20);
            }
            if (Array.isArray(patchProfile.goals)) {
                profile.goals = [...new Set([...profile.goals, ...patchProfile.goals.map((item) => normalizeText(item)).filter(Boolean)])].slice(-16);
            }
            if (Array.isArray(patchProfile.traits)) {
                profile.traits = [...new Set([...profile.traits, ...patchProfile.traits.map((item) => normalizeText(item)).filter(Boolean)])].slice(-16);
            }
            profile.updatedAt = nowIso();
        }
        for (const memoryInput of input.patch.memories ?? []) {
            const type = memoryInput.type;
            const key = normalizeText(memoryInput.key);
            const value = normalizeText(memoryInput.value);
            if (!type || !key || !value)
                continue;
            const candidate = {
                type,
                key,
                value,
                summary: normalizeText(memoryInput.summary) || `${type}: ${value}`,
                importance: clamp01(memoryInput.importance ?? 0.56),
                source: 'memory_patch',
                confidence: clamp01(memoryInput.confidence ?? 0.75),
                tags: Array.isArray(memoryInput.tags) ? memoryInput.tags.map((tag) => normalizeText(tag)).filter(Boolean) : [],
                expiresAt: memoryInput.expires_at,
                decayPerDay: 0.003,
            };
            if (this.isSensitive(`${candidate.key} ${candidate.value} ${candidate.summary}`)) {
                continue;
            }
            const saved = this.upsertMemory(input.userId, input.tenantId, candidate);
            const wasNew = Date.parse(saved.createdAt) === Date.parse(saved.updatedAt);
            if (wasNew)
                created.push(saved);
            else
                updated.push(saved);
            this.updateProfileFromCandidate(profile, candidate);
        }
        for (const event of input.patch.events ?? []) {
            const title = normalizeText(event.title);
            if (!title)
                continue;
            this.events.push({
                id: id('evt'),
                userId: input.userId,
                tenantId: input.tenantId,
                eventType: normalizeText(event.type) || 'memory_patch_event',
                title,
                detail: normalizeText(event.detail) || undefined,
                importance: clamp01(event.importance ?? 0.5),
                source: 'memory_patch',
                createdAt: event.createdAt && Number.isFinite(Date.parse(event.createdAt)) ? event.createdAt : nowIso(),
                softDeletedAt: null,
                hardDeletedAt: null,
            });
            eventsAdded += 1;
        }
        this.flush();
        return { created, updated, eventsAdded, profile };
    }
    retrieveContext(input) {
        this.applyRetentionPolicy();
        const limit = Math.max(1, Math.min(50, input.limit ?? 12));
        const qTokens = tokenSet(input.query ?? '');
        const base = this.memories.filter((memory) => (memory.userId === input.userId
            && memory.tenantId === input.tenantId
            && this.isActiveMemory(memory)));
        const scored = base.map((memory) => {
            const ageDays = daysSince(memory.lastObservedAt || memory.updatedAt);
            const recency = Math.exp(-1 * memory.decayPerDay * ageDays);
            const memoryTokens = tokenSet(`${memory.key} ${memory.value} ${memory.summary} ${(memory.tags ?? []).join(' ')}`);
            let overlap = 0;
            if (qTokens.size > 0) {
                for (const token of qTokens) {
                    if (memoryTokens.has(token))
                        overlap += 1;
                }
                overlap /= qTokens.size;
            }
            const retrievalScore = clamp01(memory.importance * 0.65 + recency * 0.25 + overlap * 0.1);
            return { ...memory, retrievalScore };
        })
            .sort((a, b) => b.retrievalScore - a.retrievalScore)
            .slice(0, limit);
        const profile = this.profiles.find((item) => (item.userId === input.userId
            && item.tenantId === input.tenantId
            && !item.deletedAt)) ?? null;
        const generatedContext = [];
        if (profile?.preferredTone)
            generatedContext.push(`Preferred tone: ${profile.preferredTone}`);
        if (profile?.pacing)
            generatedContext.push(`Preferred pacing: ${profile.pacing}`);
        if (profile?.goals?.length)
            generatedContext.push(`Current goals: ${profile.goals.slice(0, 4).join('; ')}`);
        if (profile?.traits?.length)
            generatedContext.push(`Personality signals: ${profile.traits.slice(0, 4).join('; ')}`);
        for (const item of scored.slice(0, 8)) {
            generatedContext.push(`${item.type}: ${item.summary}`);
        }
        return {
            profile,
            memories: scored,
            generatedContext,
        };
    }
    listSnapshot(input) {
        this.applyRetentionPolicy();
        const limit = Math.max(1, Math.min(200, input.limit ?? 80));
        const profile = this.profiles.find((item) => (item.userId === input.userId
            && item.tenantId === input.tenantId
            && !item.deletedAt)) ?? null;
        const events = this.events
            .filter((event) => event.userId === input.userId && event.tenantId === input.tenantId && this.isActiveEvent(event))
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
            .slice(0, limit);
        const memories = this.memories
            .filter((memory) => memory.userId === input.userId && memory.tenantId === input.tenantId && this.isActiveMemory(memory))
            .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
            .slice(0, limit);
        return {
            profile,
            events,
            memories,
            retentionPolicy: {
                maxRetentionDays: config_1.config.abigail.maxRetentionDays,
                blockedSensitiveKeywords: [...config_1.config.abigail.blockedSensitiveKeywords],
            },
        };
    }
    generateRecommendations(input) {
        const ctx = this.retrieveContext({
            userId: input.userId,
            tenantId: input.tenantId,
            limit: 10,
        });
        const items = [];
        if (ctx.profile?.goals?.length) {
            items.push({
                id: `goal-task-${Date.now()}`,
                kind: 'task',
                title: `Progress checkpoint: ${ctx.profile.goals[0]}`,
                reason: 'Derived from your active goals memory.',
            });
        }
        if (ctx.profile?.topics?.length) {
            items.push({
                id: `topic-article-${Date.now()}`,
                kind: 'article',
                title: `Read on ${ctx.profile.topics[0]}`,
                reason: 'Based on your stated preferences.',
            });
        }
        const habitMemory = ctx.memories.find((item) => item.type === 'habit');
        if (habitMemory) {
            items.push({
                id: `habit-video-${Date.now()}`,
                kind: 'video',
                title: 'Short workflow tune-up',
                reason: `Aligned with habit: ${habitMemory.value}`,
            });
        }
        if (items.length === 0) {
            items.push({
                id: 'starter-task-1',
                kind: 'task',
                title: 'Define one weekly creator goal',
                reason: 'No long-term memory yet; this helps bootstrap personalization.',
            }, {
                id: 'starter-article-1',
                kind: 'article',
                title: 'Create a preference baseline',
                reason: 'Tell Abigail your preferred pacing and topics for better responses.',
            });
        }
        return items.slice(0, 6);
    }
    forgetUserData(input) {
        const options = input.options ?? {};
        const cutoff = options.beforeTs && Number.isFinite(Date.parse(options.beforeTs))
            ? Date.parse(options.beforeTs)
            : null;
        const now = nowIso();
        let affectedMemories = 0;
        let affectedEvents = 0;
        for (const memory of this.memories) {
            if (memory.userId !== input.userId || memory.tenantId !== input.tenantId || memory.hardDeletedAt)
                continue;
            if (options.type && memory.type !== options.type)
                continue;
            if (options.source && memory.source !== options.source)
                continue;
            if (cutoff && Date.parse(memory.createdAt) > cutoff)
                continue;
            if (options.anonymize) {
                const digest = crypto_1.default
                    .createHash('sha256')
                    .update(`${config_1.config.abigail.anonymizationSalt}:${memory.id}:${memory.value}`)
                    .digest('hex')
                    .slice(0, 16);
                memory.value = `[anonymized:${digest}]`;
                memory.summary = 'Anonymized memory record';
            }
            if (options.hardDelete) {
                memory.hardDeletedAt = now;
            }
            else {
                memory.softDeletedAt = now;
            }
            memory.updatedAt = now;
            affectedMemories += 1;
        }
        for (const event of this.events) {
            if (event.userId !== input.userId || event.tenantId !== input.tenantId || event.hardDeletedAt)
                continue;
            if (options.source && event.source !== options.source)
                continue;
            if (cutoff && Date.parse(event.createdAt) > cutoff)
                continue;
            if (options.anonymize) {
                event.detail = 'Anonymized event detail';
            }
            if (options.hardDelete) {
                event.hardDeletedAt = now;
            }
            else {
                event.softDeletedAt = now;
            }
            affectedEvents += 1;
        }
        const profile = this.profiles.find((item) => item.userId === input.userId && item.tenantId === input.tenantId && !item.deletedAt);
        let profileDeleted = false;
        if (profile && !options.type && !options.source) {
            if (options.anonymize) {
                profile.preferredTone = undefined;
                profile.pacing = undefined;
                profile.topics = [];
                profile.goals = [];
                profile.traits = [];
            }
            profile.deletedAt = now;
            profile.updatedAt = now;
            profileDeleted = true;
        }
        this.flush();
        return { affectedMemories, affectedEvents, profileDeleted };
    }
    exportUserData(input) {
        this.applyRetentionPolicy();
        const profile = this.profiles.find((item) => item.userId === input.userId && item.tenantId === input.tenantId) ?? null;
        const memories = this.memories.filter((item) => item.userId === input.userId && item.tenantId === input.tenantId && !item.hardDeletedAt);
        const events = this.events.filter((item) => item.userId === input.userId && item.tenantId === input.tenantId && !item.hardDeletedAt);
        return {
            profile,
            memories,
            events,
            exportedAt: nowIso(),
        };
    }
}
exports.abigailMemoryStore = new AbigailMemoryStore();
//# sourceMappingURL=abigailMemoryStore.js.map