"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApp = createApp;
require("express-async-errors");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const morgan_1 = __importDefault(require("morgan"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const crypto_1 = __importDefault(require("crypto"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const config_1 = require("./config");
const errorHandler_1 = require("./middleware/errorHandler");
const auth_1 = __importDefault(require("./routes/auth"));
const users_1 = __importDefault(require("./routes/users"));
const videos_1 = __importDefault(require("./routes/videos"));
const feed_1 = __importDefault(require("./routes/feed"));
const discover_1 = __importDefault(require("./routes/discover"));
const origin_1 = __importDefault(require("./routes/origin"));
const membership_1 = __importDefault(require("./routes/membership"));
const admin_1 = __importDefault(require("./routes/admin"));
const nodeNetwork_1 = __importDefault(require("./routes/nodeNetwork"));
const messaging_1 = __importDefault(require("./routes/messaging"));
const studio_1 = __importDefault(require("./routes/studio"));
const live_1 = __importDefault(require("./routes/live"));
const abigail_1 = __importDefault(require("./routes/abigail"));
function parseAllowedOrigins(raw) {
    return (raw ?? '')
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean);
}
function isAllowedOrigin(origin, allowedOrigins) {
    if (isMobileAppOrigin(origin)) {
        return true;
    }
    for (const allowed of allowedOrigins) {
        if (allowed === origin)
            return true;
        // Supports entries like: https://*.originapp-9hj.pages.dev
        const wildcardMatch = allowed.match(/^(https?:\/\/)?\*\.(.+)$/i);
        if (!wildcardMatch)
            continue;
        const scheme = wildcardMatch[1] ?? '';
        const suffix = wildcardMatch[2].toLowerCase();
        try {
            const url = new URL(origin);
            const host = url.hostname.toLowerCase();
            const hostMatches = host === suffix || host.endsWith(`.${suffix}`);
            const schemeMatches = !scheme || `${url.protocol}//` === scheme.toLowerCase();
            if (hostMatches && schemeMatches)
                return true;
        }
        catch {
            // Ignore invalid origin values.
        }
    }
    return false;
}
function isMobileAppOrigin(origin) {
    const normalized = origin.trim().toLowerCase();
    if (!normalized)
        return false;
    if (normalized.startsWith('exp://'))
        return true;
    if (normalized.startsWith('capacitor://'))
        return true;
    if (normalized.startsWith('ionic://'))
        return true;
    if (normalized === 'null')
        return true;
    // WebView and local-device development hosts.
    return (normalized.startsWith('http://localhost')
        || normalized.startsWith('http://127.0.0.1')
        || normalized.startsWith('http://10.0.2.2')
        || normalized.startsWith('http://192.168.')
        || normalized.startsWith('http://172.16.')
        || normalized.startsWith('http://172.17.')
        || normalized.startsWith('http://172.18.')
        || normalized.startsWith('http://172.19.')
        || normalized.startsWith('http://172.2')
        || normalized.startsWith('http://172.30.')
        || normalized.startsWith('http://172.31.'));
}
function normalizeCid(value) {
    return value.trim().toLowerCase();
}
function computeSha256Cid(bytes) {
    const digest = crypto_1.default.createHash('sha256').update(bytes).digest('hex');
    return `sha256:${digest}`;
}
function loadServedLedgers() {
    const map = new Map();
    const candidates = [
        {
            kind: 'license',
            ledgerPath: process.env.ORIGIN_LICENSE_LEDGER_PATH
                ?? path_1.default.resolve(process.cwd(), 'ledgers', 'bootstrap_v1.json'),
            cidPath: process.env.ORIGIN_LICENSE_LEDGER_CID_PATH,
        },
        {
            kind: 'governance',
            ledgerPath: process.env.ORIGIN_GOVERNANCE_LEDGER_PATH
                ?? path_1.default.resolve(process.cwd(), 'ledgers', 'governance_v1.json'),
            cidPath: process.env.ORIGIN_GOVERNANCE_LEDGER_CID_PATH
                ?? path_1.default.resolve(process.cwd(), 'ledgers', 'governance_v1.cid'),
        },
    ];
    for (const candidate of candidates) {
        if (!fs_1.default.existsSync(candidate.ledgerPath))
            continue;
        const bytes = fs_1.default.readFileSync(candidate.ledgerPath);
        const computedCid = normalizeCid(computeSha256Cid(bytes));
        map.set(computedCid, { cid: computedCid, bytes, kind: candidate.kind });
        if (candidate.cidPath && fs_1.default.existsSync(candidate.cidPath)) {
            const rawCid = fs_1.default.readFileSync(candidate.cidPath, 'utf-8').trim();
            if (rawCid) {
                map.set(normalizeCid(rawCid), { cid: normalizeCid(rawCid), bytes, kind: candidate.kind });
            }
        }
    }
    return map;
}
function createApp() {
    const app = (0, express_1.default)();
    const allowedOrigins = parseAllowedOrigins(process.env.ALLOWED_ORIGINS);
    const servedLedgers = loadServedLedgers();
    // --- Security & logging middleware ---
    app.use((0, helmet_1.default)());
    app.use((0, cors_1.default)({
        origin: config_1.config.nodeEnv === 'production'
            ? (requestOrigin, callback) => {
                if (!requestOrigin) {
                    callback(null, true);
                    return;
                }
                if (isAllowedOrigin(requestOrigin, allowedOrigins)) {
                    callback(null, true);
                    return;
                }
                callback(new Error('CORS origin not allowed'));
            }
            : '*',
        credentials: true,
    }));
    app.use((0, morgan_1.default)(config_1.config.nodeEnv === 'production' ? 'combined' : 'dev'));
    // --- Rate limiting ---
    app.use((0, express_rate_limit_1.default)({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 500,
        standardHeaders: true,
        legacyHeaders: false,
    }));
    // Stripe webhook must receive the raw body for signature verification.
    app.use('/api/membership/webhook', express_1.default.raw({ type: 'application/json' }));
    // --- Body parsing ---
    app.use(express_1.default.json({ limit: '1mb' }));
    app.use(express_1.default.urlencoded({ extended: true }));
    // --- Static uploads ---
    const uploadsDir = path_1.default.resolve(config_1.config.storage.localDir);
    if (!fs_1.default.existsSync(uploadsDir)) {
        fs_1.default.mkdirSync(uploadsDir, { recursive: true });
    }
    app.use('/uploads', express_1.default.static(uploadsDir));
    // --- Routes ---
    app.use('/api/auth', auth_1.default);
    app.use('/api/users', users_1.default);
    app.use('/api/membership', membership_1.default);
    app.use('/api/admin', admin_1.default);
    app.use('/api/messaging', messaging_1.default);
    app.use('/api/studio', studio_1.default);
    app.use('/api/live', live_1.default);
    app.use('/api/videos', videos_1.default);
    app.use('/api/feed', feed_1.default);
    app.use('/api/discover', discover_1.default);
    app.use('/api/origin', origin_1.default);
    app.use('/', abigail_1.default);
    app.use('/', nodeNetwork_1.default);
    // --- Node network endpoints (basic full-node serving) ---
    app.get('/health', (_req, res) => {
        res.json({ status: 'ok', role: 'origin-social-node', ts: new Date().toISOString() });
    });
    app.get('/ledger', (_req, res) => {
        const items = [...servedLedgers.values()].map((entry) => ({ cid: entry.cid, kind: entry.kind }));
        res.json({ ledgers: items });
    });
    app.get('/ledger/:cid', (req, res) => {
        const key = normalizeCid(req.params.cid);
        const entry = servedLedgers.get(key);
        if (!entry) {
            res.status(404).json({ error: 'Ledger CID not found on this node' });
            return;
        }
        res.type('application/json').send(entry.bytes);
    });
    app.get('/ipfs/:cid', (req, res) => {
        const key = normalizeCid(req.params.cid);
        const entry = servedLedgers.get(key);
        if (!entry) {
            res.status(404).json({ error: 'Ledger CID not found on this node' });
            return;
        }
        res.type('application/json').send(entry.bytes);
    });
    // --- Health check ---
    app.get('/healthz', (_req, res) => {
        res.json({ status: 'ok', ts: new Date().toISOString() });
    });
    app.get('/api/healthz', (_req, res) => {
        res.json({ status: 'ok', ts: new Date().toISOString() });
    });
    // --- Error handler (must be last) ---
    app.use(errorHandler_1.errorHandler);
    return app;
}
const app = createApp();
if (require.main === module) {
    (0, config_1.assertRuntimeConfig)();
    app.listen(config_1.config.port, () => {
        console.log(`[origin-social/server] listening on port ${config_1.config.port}`);
    });
}
exports.default = app;
//# sourceMappingURL=index.js.map