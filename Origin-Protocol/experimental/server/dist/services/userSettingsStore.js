"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.userSettingsStore = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const DATA_DIR = path_1.default.resolve('.data');
const STORE_FILE = path_1.default.join(DATA_DIR, 'user-settings.json');
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
function persist(payload) {
    ensureDataDir();
    fs_1.default.writeFileSync(STORE_FILE, JSON.stringify(payload, null, 2), 'utf8');
}
function id(prefix) {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}
function nowIso() {
    return new Date().toISOString();
}
function defaultSettings(input) {
    const ts = nowIso();
    const currentSessionId = id('session');
    const sessionSeed = {
        id: currentSessionId,
        deviceName: 'Current browser',
        location: 'Unknown',
        ipAddress: '0.0.0.0',
        lastSeenAt: ts,
        current: true,
    };
    return {
        userId: input.userId,
        personalInformation: {
            displayName: input.displayName,
            username: input.username,
            bio: input.bio ?? '',
            profilePhoto: input.avatarUrl ?? '',
            bannerPhoto: '',
            pronouns: '',
            birthday: '',
            location: '',
            contactEmail: input.email,
            phoneNumber: '',
        },
        privacySafety: {
            whoCanMessageMe: 'everyone',
            whoCanSeeMyPosts: 'public',
            blockedUsers: [],
            mutedUsers: [],
            twoFactorAuthEnabled: false,
            loginAlertsEnabled: true,
            pauseAbigailMemoryCollection: false,
        },
        preferences: {
            notificationMode: 'important',
            feedTuning: 'balanced',
            contentPreferences: [],
            theme: 'dark',
            language: 'en',
            sensitiveContent: 'moderate',
            abigailTone: 'concise',
        },
        billingPurchases: {
            subscriptions: [],
            paymentMethods: [],
            billingHistory: [],
            receipts: [],
            autoRenewEnabled: true,
        },
        devicesSessions: {
            activeSessions: [sessionSeed],
            deviceList: [sessionSeed],
            loginHistory: [
                {
                    id: id('login'),
                    deviceName: 'Current browser',
                    location: 'Unknown',
                    ipAddress: '0.0.0.0',
                    createdAt: ts,
                },
            ],
        },
        abigailPersonalization: {
            userGoals: [],
            habits: [],
            interests: [],
            learningStyle: '',
            memorySummary: 'No summary yet.',
        },
        accountManagement: {
            legalAgreementsAcceptedAt: ts,
            ageVerificationStatus: 'pending',
        },
        updatedAt: ts,
    };
}
function mergeDeep(base, patch) {
    const out = { ...base };
    for (const [key, patchValue] of Object.entries(patch)) {
        if (patchValue === undefined)
            continue;
        const baseValue = out[key];
        if (patchValue
            && typeof patchValue === 'object'
            && !Array.isArray(patchValue)
            && baseValue
            && typeof baseValue === 'object'
            && !Array.isArray(baseValue)) {
            out[key] = mergeDeep(baseValue, patchValue);
        }
        else {
            out[key] = patchValue;
        }
    }
    return out;
}
class UserSettingsStore {
    constructor() {
        this.items = load().items;
        this.flush();
    }
    flush() {
        persist({ items: this.items });
    }
    ensure(user) {
        let existing = this.items.find((item) => item.userId === user.id);
        if (existing)
            return existing;
        existing = defaultSettings({
            userId: user.id,
            displayName: user.displayName,
            username: user.username,
            email: user.email,
            bio: user.bio,
            avatarUrl: user.avatarUrl,
        });
        this.items.push(existing);
        this.flush();
        return existing;
    }
    get(user) {
        return this.ensure(user);
    }
    update(user, patch) {
        const existing = this.ensure(user);
        const merged = mergeDeep(existing, patch);
        merged.userId = user.id;
        merged.updatedAt = nowIso();
        const idx = this.items.findIndex((item) => item.userId === user.id);
        this.items[idx] = merged;
        this.flush();
        return merged;
    }
    revokeSession(user, sessionId) {
        const existing = this.ensure(user);
        existing.devicesSessions.activeSessions = existing.devicesSessions.activeSessions.filter((item) => item.id !== sessionId || item.current);
        existing.devicesSessions.deviceList = existing.devicesSessions.deviceList.filter((item) => item.id !== sessionId || item.current);
        existing.updatedAt = nowIso();
        this.flush();
        return existing;
    }
    export(user) {
        const settings = this.ensure(user);
        return {
            settings,
            exportedAt: nowIso(),
        };
    }
    delete(userId) {
        const idx = this.items.findIndex((item) => item.userId === userId);
        if (idx >= 0) {
            this.items.splice(idx, 1);
            this.flush();
        }
    }
}
exports.userSettingsStore = new UserSettingsStore();
//# sourceMappingURL=userSettingsStore.js.map