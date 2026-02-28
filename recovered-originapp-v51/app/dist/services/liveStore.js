"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.liveStore = exports.LiveStore = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const uuid_1 = require("uuid");
const DATA_DIR = path_1.default.resolve('.data');
const STORE_FILE = path_1.default.join(DATA_DIR, 'live.json');
function ensureDataDir() {
    if (!fs_1.default.existsSync(DATA_DIR)) {
        fs_1.default.mkdirSync(DATA_DIR, { recursive: true });
    }
}
function load() {
    try {
        if (!fs_1.default.existsSync(STORE_FILE)) {
            return { sessions: [], comments: [], sessionLikes: [], commentLikes: [] };
        }
        const raw = fs_1.default.readFileSync(STORE_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return {
            sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
            comments: Array.isArray(parsed.comments) ? parsed.comments : [],
            sessionLikes: Array.isArray(parsed.sessionLikes) ? parsed.sessionLikes : [],
            commentLikes: Array.isArray(parsed.commentLikes) ? parsed.commentLikes : [],
        };
    }
    catch {
        return { sessions: [], comments: [], sessionLikes: [], commentLikes: [] };
    }
}
class LiveStore {
    constructor() {
        this.sessions = new Map();
        this.comments = new Map();
        this.sessionLikes = new Set(); // `${sessionId}:${userId}`
        this.commentLikes = new Set(); // `${commentId}:${userId}`
        const initial = load();
        initial.sessions.forEach((item) => this.sessions.set(item.id, item));
        initial.comments.forEach((item) => this.comments.set(item.id, item));
        initial.sessionLikes.forEach((item) => this.sessionLikes.add(item));
        initial.commentLikes.forEach((item) => this.commentLikes.add(item));
        this.flush();
    }
    flush() {
        ensureDataDir();
        const payload = {
            sessions: [...this.sessions.values()],
            comments: [...this.comments.values()],
            sessionLikes: [...this.sessionLikes.values()],
            commentLikes: [...this.commentLikes.values()],
        };
        fs_1.default.writeFileSync(STORE_FILE, JSON.stringify(payload, null, 2), 'utf8');
    }
    createSession(input) {
        const now = new Date().toISOString();
        const session = {
            id: (0, uuid_1.v4)(),
            hostUserId: input.hostUserId,
            title: input.title,
            description: input.description?.trim() || null,
            status: 'live',
            startedAt: now,
            endedAt: null,
            viewerIds: [input.hostUserId],
            peakViewerCount: 1,
        };
        this.sessions.set(session.id, session);
        this.flush();
        return session;
    }
    getSession(sessionId) {
        return this.sessions.get(sessionId) ?? null;
    }
    listSessions(status = 'live', limit = 50) {
        const rows = [...this.sessions.values()]
            .filter((item) => (status === 'all' ? true : item.status === status))
            .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
        return rows.slice(0, Math.max(1, Math.min(limit, 200)));
    }
    findLiveSessionByHost(hostUserId) {
        return this.listSessions('live', 200).find((item) => item.hostUserId === hostUserId) ?? null;
    }
    endSession(sessionId) {
        const existing = this.sessions.get(sessionId);
        if (!existing)
            return null;
        if (existing.status === 'ended')
            return existing;
        const updated = {
            ...existing,
            status: 'ended',
            endedAt: new Date().toISOString(),
            viewerIds: [existing.hostUserId],
        };
        this.sessions.set(sessionId, updated);
        this.flush();
        return updated;
    }
    setViewerPresence(sessionId, userId, active) {
        const existing = this.sessions.get(sessionId);
        if (!existing)
            return null;
        if (existing.status !== 'live')
            return existing;
        const next = new Set(existing.viewerIds);
        if (active)
            next.add(userId);
        else if (userId !== existing.hostUserId)
            next.delete(userId);
        const viewerIds = [...next.values()];
        const updated = {
            ...existing,
            viewerIds,
            peakViewerCount: Math.max(existing.peakViewerCount, viewerIds.length),
        };
        this.sessions.set(sessionId, updated);
        this.flush();
        return updated;
    }
    createComment(input) {
        const comment = {
            id: (0, uuid_1.v4)(),
            sessionId: input.sessionId,
            authorId: input.authorId,
            text: input.text,
            parentId: input.parentId ?? null,
            createdAt: new Date().toISOString(),
        };
        this.comments.set(comment.id, comment);
        this.flush();
        return comment;
    }
    getComment(commentId) {
        return this.comments.get(commentId) ?? null;
    }
    listComments(sessionId) {
        return [...this.comments.values()]
            .filter((item) => item.sessionId === sessionId)
            .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    }
    toggleSessionLike(sessionId, userId) {
        const key = `${sessionId}:${userId}`;
        const liked = this.sessionLikes.has(key);
        if (liked) {
            this.sessionLikes.delete(key);
            this.flush();
            return false;
        }
        this.sessionLikes.add(key);
        this.flush();
        return true;
    }
    toggleCommentLike(commentId, userId) {
        const key = `${commentId}:${userId}`;
        const liked = this.commentLikes.has(key);
        if (liked) {
            this.commentLikes.delete(key);
            this.flush();
            return false;
        }
        this.commentLikes.add(key);
        this.flush();
        return true;
    }
    countSessionLikes(sessionId) {
        return [...this.sessionLikes.values()].filter((key) => key.startsWith(`${sessionId}:`)).length;
    }
    hasUserLikedSession(sessionId, userId) {
        return this.sessionLikes.has(`${sessionId}:${userId}`);
    }
    countCommentLikes(commentId) {
        return [...this.commentLikes.values()].filter((key) => key.startsWith(`${commentId}:`)).length;
    }
    hasUserLikedComment(commentId, userId) {
        return this.commentLikes.has(`${commentId}:${userId}`);
    }
}
exports.LiveStore = LiveStore;
exports.liveStore = new LiveStore();
//# sourceMappingURL=liveStore.js.map