"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.syncHistoryStore = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const DATA_DIR = path_1.default.resolve('.data');
const STORE_FILE = path_1.default.join(DATA_DIR, 'sync_history.json');
const MAX_PER_USER = 24;
function ensureDataDir() {
    if (!fs_1.default.existsSync(DATA_DIR)) {
        fs_1.default.mkdirSync(DATA_DIR, { recursive: true });
    }
}
function load() {
    try {
        if (!fs_1.default.existsSync(STORE_FILE)) {
            return { items: [] };
        }
        const raw = fs_1.default.readFileSync(STORE_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return { items: Array.isArray(parsed.items) ? parsed.items : [] };
    }
    catch {
        return { items: [] };
    }
}
function save(payload) {
    ensureDataDir();
    fs_1.default.writeFileSync(STORE_FILE, JSON.stringify(payload, null, 2), 'utf8');
}
exports.syncHistoryStore = {
    listByUser(userId) {
        return load().items
            .filter((item) => item.userId === userId)
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },
    append(entry) {
        const payload = load();
        const item = {
            ...entry,
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            createdAt: new Date().toISOString(),
        };
        const others = payload.items.filter((existing) => existing.userId !== entry.userId);
        const sameUser = payload.items
            .filter((existing) => existing.userId === entry.userId)
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        const mergedSameUser = [item, ...sameUser].slice(0, MAX_PER_USER);
        const merged = [...others, ...mergedSameUser].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        save({ items: merged });
        return mergedSameUser;
    },
    clearByUser(userId) {
        const payload = load();
        const remaining = payload.items.filter((item) => item.userId !== userId);
        save({ items: remaining });
    },
};
//# sourceMappingURL=syncHistoryStore.js.map