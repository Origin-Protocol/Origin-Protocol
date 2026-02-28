"use strict";
/**
 * In-memory store used during development.
 *
 * Durable local persistence store used during development.
 *
 * Persists to `.data/store.json` inside the server workspace.
 * The public interface remains Map/Set-compatible so route code
 * does not need changes.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.db = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const DATA_DIR = path_1.default.resolve('.data');
const STORE_FILE = path_1.default.join(DATA_DIR, 'store.json');
function ensureDataDir() {
    if (!fs_1.default.existsSync(DATA_DIR)) {
        fs_1.default.mkdirSync(DATA_DIR, { recursive: true });
    }
}
function loadPersisted() {
    try {
        if (!fs_1.default.existsSync(STORE_FILE)) {
            return { users: [], videos: [], comments: [], likes: [] };
        }
        const raw = fs_1.default.readFileSync(STORE_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return {
            users: Array.isArray(parsed.users) ? parsed.users : [],
            videos: Array.isArray(parsed.videos) ? parsed.videos : [],
            comments: Array.isArray(parsed.comments) ? parsed.comments : [],
            likes: Array.isArray(parsed.likes) ? parsed.likes : [],
        };
    }
    catch {
        return { users: [], videos: [], comments: [], likes: [] };
    }
}
function persist(payload) {
    ensureDataDir();
    fs_1.default.writeFileSync(STORE_FILE, JSON.stringify(payload, null, 2), 'utf8');
}
class PersistedMap extends Map {
    constructor(entries, onMutate) {
        super();
        this.onMutate = onMutate;
        if (entries) {
            for (const [key, value] of entries) {
                super.set(key, value);
            }
        }
    }
    set(key, value) {
        const result = super.set(key, value);
        this.onMutate();
        return result;
    }
    delete(key) {
        const result = super.delete(key);
        if (result) {
            this.onMutate();
        }
        return result;
    }
    clear() {
        if (this.size > 0) {
            super.clear();
            this.onMutate();
            return;
        }
        super.clear();
    }
}
class PersistedSet extends Set {
    constructor(values, onMutate) {
        super();
        this.onMutate = onMutate;
        if (values) {
            for (const value of values) {
                super.add(value);
            }
        }
    }
    add(value) {
        const had = this.has(value);
        const result = super.add(value);
        if (!had) {
            this.onMutate();
        }
        return result;
    }
    delete(value) {
        const result = super.delete(value);
        if (result) {
            this.onMutate();
        }
        return result;
    }
    clear() {
        if (this.size > 0) {
            super.clear();
            this.onMutate();
            return;
        }
        super.clear();
    }
}
const initial = loadPersisted();
function flush() {
    persist({
        users: [...exports.db.users.values()],
        videos: [...exports.db.videos.values()],
        comments: [...exports.db.comments.values()],
        likes: [...exports.db.likes.values()],
    });
}
exports.db = {
    users: new PersistedMap(initial.users.map((user) => [user.id, user]), flush),
    videos: new PersistedMap(initial.videos.map((video) => [video.id, video]), flush),
    comments: new PersistedMap(initial.comments.map((comment) => [comment.id, comment]), flush),
    likes: new PersistedSet(initial.likes, flush), // `${userId}:${videoId}`
};
// Ensure file exists even when starting with empty state.
flush();
//# sourceMappingURL=store.js.map