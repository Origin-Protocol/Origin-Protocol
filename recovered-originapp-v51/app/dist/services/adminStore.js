"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.adminStore = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const DATA_DIR = path_1.default.resolve('.data');
const STORE_FILE = path_1.default.join(DATA_DIR, 'admin_panel.json');
const MAX_USAGE_EVENTS = 5000;
const MAX_ERROR_LOGS = 2000;
const MAX_REPORTS = 5000;
const MAX_PAYOUT_RUNS = 120;
function defaultPayoutConfig() {
    return {
        enabled: false,
        thresholds: {
            minMonthlyNetProfit: 25000,
            minMonthlyRevenue: 100000,
            minActiveMonthlyUsers: 500000,
            minActiveCreators: 10000,
            minMonthlyApiVerifications: 1000000000,
        },
        percentages: {
            subscriptionRevenuePct: 0.2,
            apiUsageRevenuePct: 0.15,
            boostRevenuePct: 0.1,
            monthlyProfitPct: 0.1,
        },
    };
}
function defaultRecommendationConfig() {
    return {
        weights: {
            interest: 0.28,
            community: 0.2,
            provenance: 0.2,
            health: 0.22,
            equity: 0.1,
        },
        fairnessRotationFrequency: 4,
        creatorDominanceCap: 2,
        spotlightBoostVisibility: 1,
        healthDownrankThreshold: -0.3,
        aiAdaptiveEnabled: true,
    };
}
function ensureDataDir() {
    if (!fs_1.default.existsSync(DATA_DIR)) {
        fs_1.default.mkdirSync(DATA_DIR, { recursive: true });
    }
}
function load() {
    try {
        if (!fs_1.default.existsSync(STORE_FILE)) {
            return {
                toolVersions: [],
                usageEvents: [],
                errorLogs: [],
                bannedUserIds: [],
                promotedAdminUserIds: [],
                reports: [],
                payoutConfig: defaultPayoutConfig(),
                payoutRuns: [],
                flaggedAccounts: [],
                recommendationConfig: defaultRecommendationConfig(),
            };
        }
        const raw = fs_1.default.readFileSync(STORE_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return {
            toolVersions: Array.isArray(parsed.toolVersions) ? parsed.toolVersions : [],
            usageEvents: Array.isArray(parsed.usageEvents) ? parsed.usageEvents : [],
            errorLogs: Array.isArray(parsed.errorLogs) ? parsed.errorLogs : [],
            bannedUserIds: Array.isArray(parsed.bannedUserIds) ? parsed.bannedUserIds : [],
            promotedAdminUserIds: Array.isArray(parsed.promotedAdminUserIds) ? parsed.promotedAdminUserIds : [],
            reports: Array.isArray(parsed.reports) ? parsed.reports : [],
            payoutConfig: parsed.payoutConfig ? {
                enabled: Boolean(parsed.payoutConfig.enabled),
                thresholds: {
                    ...defaultPayoutConfig().thresholds,
                    ...(parsed.payoutConfig.thresholds ?? {}),
                },
                percentages: {
                    ...defaultPayoutConfig().percentages,
                    ...(parsed.payoutConfig.percentages ?? {}),
                },
            } : defaultPayoutConfig(),
            payoutRuns: Array.isArray(parsed.payoutRuns) ? parsed.payoutRuns : [],
            flaggedAccounts: Array.isArray(parsed.flaggedAccounts) ? parsed.flaggedAccounts : [],
            recommendationConfig: parsed.recommendationConfig ? {
                ...defaultRecommendationConfig(),
                ...parsed.recommendationConfig,
                weights: {
                    ...defaultRecommendationConfig().weights,
                    ...(parsed.recommendationConfig.weights ?? {}),
                },
            } : defaultRecommendationConfig(),
        };
    }
    catch {
        return {
            toolVersions: [],
            usageEvents: [],
            errorLogs: [],
            bannedUserIds: [],
            promotedAdminUserIds: [],
            reports: [],
            payoutConfig: defaultPayoutConfig(),
            payoutRuns: [],
            flaggedAccounts: [],
            recommendationConfig: defaultRecommendationConfig(),
        };
    }
}
function save(payload) {
    ensureDataDir();
    fs_1.default.writeFileSync(STORE_FILE, JSON.stringify(payload, null, 2), 'utf8');
}
function id(prefix) {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}
exports.adminStore = {
    listToolVersions() {
        return load().toolVersions.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },
    createToolVersion(input) {
        const payload = load();
        const isLatest = Boolean(input.isLatest ?? true);
        if (isLatest) {
            payload.toolVersions = payload.toolVersions.map((item) => ({ ...item, isLatest: false }));
        }
        const created = {
            id: id('toolver'),
            version: input.version.trim(),
            notes: input.notes?.trim() || undefined,
            fileName: input.fileName?.trim() || undefined,
            isLatest,
            forceUpdate: Boolean(input.forceUpdate ?? false),
            downloadCount: 0,
            createdAt: new Date().toISOString(),
        };
        payload.toolVersions.unshift(created);
        save(payload);
        return created;
    },
    updateToolVersion(versionId, updates) {
        const payload = load();
        const idx = payload.toolVersions.findIndex((item) => item.id === versionId);
        if (idx < 0)
            return null;
        if (updates.isLatest) {
            payload.toolVersions = payload.toolVersions.map((item) => ({ ...item, isLatest: false }));
        }
        const next = {
            ...payload.toolVersions[idx],
            ...(typeof updates.isLatest === 'boolean' ? { isLatest: updates.isLatest } : {}),
            ...(typeof updates.forceUpdate === 'boolean' ? { forceUpdate: updates.forceUpdate } : {}),
        };
        payload.toolVersions[idx] = next;
        save(payload);
        return next;
    },
    incrementToolVersionDownload(versionId) {
        const payload = load();
        const idx = payload.toolVersions.findIndex((item) => item.id === versionId);
        if (idx < 0)
            return null;
        const next = {
            ...payload.toolVersions[idx],
            downloadCount: payload.toolVersions[idx].downloadCount + 1,
        };
        payload.toolVersions[idx] = next;
        save(payload);
        return next;
    },
    appendUsageEvent(input) {
        const payload = load();
        const created = {
            id: id('usage'),
            metric: input.metric.trim(),
            value: Number.isFinite(input.value) ? Number(input.value) : 1,
            userId: input.userId,
            source: input.source,
            createdAt: new Date().toISOString(),
        };
        payload.usageEvents.unshift(created);
        payload.usageEvents = payload.usageEvents.slice(0, MAX_USAGE_EVENTS);
        save(payload);
        return created;
    },
    listUsageEvents(limit = 200) {
        return load().usageEvents
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
            .slice(0, Math.max(1, Math.min(limit, 2000)));
    },
    appendErrorLog(input) {
        const payload = load();
        const created = {
            id: id('err'),
            source: input.source,
            message: input.message,
            level: input.level ?? 'error',
            meta: input.meta,
            createdAt: new Date().toISOString(),
        };
        payload.errorLogs.unshift(created);
        payload.errorLogs = payload.errorLogs.slice(0, MAX_ERROR_LOGS);
        save(payload);
        return created;
    },
    listErrorLogs(limit = 200) {
        return load().errorLogs
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
            .slice(0, Math.max(1, Math.min(limit, 2000)));
    },
    listReports(status = 'all', limit = 500) {
        const items = load().reports.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        const filtered = status === 'all' ? items : items.filter((item) => item.status === status);
        return filtered.slice(0, Math.max(1, Math.min(limit, 5000)));
    },
    createReport(input) {
        const payload = load();
        const created = {
            id: id('report'),
            videoId: input.videoId,
            reporterUserId: input.reporterUserId,
            reason: input.reason,
            notes: input.notes,
            status: 'open',
            createdAt: new Date().toISOString(),
        };
        payload.reports.unshift(created);
        payload.reports = payload.reports.slice(0, MAX_REPORTS);
        save(payload);
        return created;
    },
    resolveReport(reportId, resolvedByUserId) {
        const payload = load();
        const idx = payload.reports.findIndex((item) => item.id === reportId);
        if (idx < 0)
            return null;
        const next = {
            ...payload.reports[idx],
            status: 'resolved',
            resolvedAt: new Date().toISOString(),
            resolvedByUserId,
        };
        payload.reports[idx] = next;
        save(payload);
        return next;
    },
    isUserBanned(userId) {
        return load().bannedUserIds.includes(userId);
    },
    listBannedUserIds() {
        return [...load().bannedUserIds];
    },
    isPromotedAdmin(userId) {
        return load().promotedAdminUserIds.includes(userId);
    },
    listPromotedAdminUserIds() {
        return [...load().promotedAdminUserIds];
    },
    setPromotedAdmin(userId, active) {
        const payload = load();
        const has = payload.promotedAdminUserIds.includes(userId);
        if (active && !has) {
            payload.promotedAdminUserIds.push(userId);
            save(payload);
            return true;
        }
        if (!active && has) {
            payload.promotedAdminUserIds = payload.promotedAdminUserIds.filter((item) => item !== userId);
            save(payload);
            return true;
        }
        return false;
    },
    setUserBan(userId, banned) {
        const payload = load();
        const has = payload.bannedUserIds.includes(userId);
        if (banned && !has) {
            payload.bannedUserIds.push(userId);
            save(payload);
            return true;
        }
        if (!banned && has) {
            payload.bannedUserIds = payload.bannedUserIds.filter((item) => item !== userId);
            save(payload);
            return true;
        }
        return false;
    },
    getPayoutConfig() {
        return load().payoutConfig;
    },
    updatePayoutConfig(input) {
        const payload = load();
        const current = payload.payoutConfig;
        payload.payoutConfig = {
            enabled: typeof input.enabled === 'boolean' ? input.enabled : current.enabled,
            thresholds: {
                ...current.thresholds,
                ...(input.thresholds ?? {}),
            },
            percentages: {
                ...current.percentages,
                ...(input.percentages ?? {}),
            },
        };
        save(payload);
        return payload.payoutConfig;
    },
    listPayoutRuns(limit = 24) {
        return load().payoutRuns
            .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
            .slice(0, Math.max(1, Math.min(limit, MAX_PAYOUT_RUNS)));
    },
    getLatestPayoutRun() {
        const runs = this.listPayoutRuns(1);
        return runs.length > 0 ? runs[0] : null;
    },
    appendPayoutRun(run) {
        const payload = load();
        const created = {
            ...run,
            id: id('payout'),
            createdAt: new Date().toISOString(),
        };
        payload.payoutRuns.unshift(created);
        payload.payoutRuns = payload.payoutRuns.slice(0, MAX_PAYOUT_RUNS);
        save(payload);
        return created;
    },
    listFlaggedAccounts(status = 'all', limit = 500) {
        const rows = load().flaggedAccounts.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
        const filtered = status === 'all' ? rows : rows.filter((row) => row.status === status);
        return filtered.slice(0, Math.max(1, Math.min(limit, 5000)));
    },
    upsertFlaggedAccount(input) {
        const payload = load();
        const idx = payload.flaggedAccounts.findIndex((row) => row.userId === input.userId);
        const now = new Date().toISOString();
        if (idx >= 0) {
            const next = {
                ...payload.flaggedAccounts[idx],
                reason: input.reason || payload.flaggedAccounts[idx].reason,
                status: input.status ?? payload.flaggedAccounts[idx].status,
                updatedAt: now,
            };
            payload.flaggedAccounts[idx] = next;
            save(payload);
            return next;
        }
        const created = {
            userId: input.userId,
            reason: input.reason,
            status: input.status ?? 'open',
            createdAt: now,
            updatedAt: now,
        };
        payload.flaggedAccounts.unshift(created);
        save(payload);
        return created;
    },
    isCreatorFlagged(userId) {
        return load().flaggedAccounts.some((row) => row.userId === userId && row.status !== 'cleared');
    },
    getRecommendationConfig() {
        return load().recommendationConfig;
    },
    updateRecommendationConfig(input) {
        const payload = load();
        const current = payload.recommendationConfig;
        payload.recommendationConfig = {
            ...current,
            ...input,
            weights: {
                ...current.weights,
                ...(input.weights ?? {}),
            },
        };
        save(payload);
        return payload.recommendationConfig;
    },
};
//# sourceMappingURL=adminStore.js.map