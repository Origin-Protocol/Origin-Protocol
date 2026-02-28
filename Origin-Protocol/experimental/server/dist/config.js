"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
exports.assertRuntimeConfig = assertRuntimeConfig;
const dotenv = __importStar(require("dotenv"));
dotenv.config();
function isTruthy(value) {
    if (!value)
        return false;
    const normalized = value.trim().toLowerCase();
    return normalized === '1' || normalized === 'true' || normalized === 'yes';
}
function parseCsv(value) {
    if (!value)
        return [];
    return value
        .split(',')
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
}
function parseIntOr(value, fallback) {
    const parsed = Number.parseInt((value ?? '').trim(), 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
function parseFloatOr(value, fallback) {
    const parsed = Number.parseFloat((value ?? '').trim());
    return Number.isFinite(parsed) ? parsed : fallback;
}
exports.config = {
    port: parseInt(process.env.PORT ?? '4000', 10),
    nodeEnv: process.env.NODE_ENV ?? 'development',
    database: {
        usePrisma: (process.env.USE_PRISMA ?? '0') === '1',
    },
    jwt: {
        secret: process.env.JWT_SECRET ?? 'change-me-in-production',
        expiresIn: process.env.JWT_EXPIRES_IN ?? '7d',
    },
    origin: {
        ledgerUrl: process.env.ORIGIN_LEDGER_URL ?? 'http://127.0.0.1:9050',
        platformId: process.env.ORIGIN_PLATFORM_ID ?? 'origin-social',
    },
    ingest: {
        apiKey: process.env.ORIGIN_INGEST_API_KEY ?? '',
    },
    cloudflareStream: {
        apiToken: process.env.CLOUDFLARE_STREAM_API_TOKEN ?? '',
        accountId: process.env.CLOUDFLARE_ACCOUNT_ID ?? '',
        subdomain: process.env.CLOUDFLARE_STREAM_SUBDOMAIN ?? '',
    },
    moderation: {
        cloudflareApiUrl: process.env.CLOUDFLARE_MODERATION_API_URL ?? '',
        cloudflareApiToken: process.env.CLOUDFLARE_MODERATION_API_TOKEN ?? '',
        cloudflareAccountId: process.env.CLOUDFLARE_MODERATION_ACCOUNT_ID ?? process.env.CLOUDFLARE_ACCOUNT_ID ?? '',
        cloudflareModel: process.env.CLOUDFLARE_MODERATION_MODEL ?? '@cf/meta/llama-guard-3-8b',
        timeoutMs: parseIntOr(process.env.CLOUDFLARE_MODERATION_TIMEOUT_MS, 4500),
        retries: parseIntOr(process.env.CLOUDFLARE_MODERATION_RETRIES, 1),
        blockedKeywords: parseCsv(process.env.MODERATION_BLOCKED_TERMS
            ?? 'porn,porno,xxx,explicit sex,adult content,escort,prostitution,onlyfans,camgirl,camboy,nsfw'),
    },
    storage: {
        driver: (process.env.STORAGE_DRIVER ?? 'local'),
        localDir: process.env.STORAGE_LOCAL_DIR ?? './uploads',
        s3: {
            bucket: process.env.S3_BUCKET ?? '',
            region: process.env.S3_REGION ?? 'us-east-1',
            accessKey: process.env.S3_ACCESS_KEY ?? '',
            secretKey: process.env.S3_SECRET_KEY ?? '',
            endpoint: process.env.S3_ENDPOINT ?? '',
        },
    },
    membership: {
        stripeSecretKey: process.env.STRIPE_SECRET_KEY ?? '',
        stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY ?? '',
        stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET ?? '',
        stripePriceId: process.env.STRIPE_PRICE_ID ?? '',
        stripePriceLookupKey: process.env.STRIPE_PRICE_LOOKUP_KEY ?? '',
        stripeDefaultCreatorProductId: process.env.STRIPE_DEFAULT_CREATOR_PRODUCT_ID ?? 'prod_U2RmK26Xfl3yAo',
        stripeMeterId: process.env.STRIPE_METER_ID ?? '',
        stripeMeterEventName: process.env.STRIPE_METER_EVENT_NAME ?? 'api_requests',
        frontendBaseUrl: process.env.FRONTEND_URL ?? 'http://localhost:5173',
        stripeSuccessUrl: process.env.STRIPE_SUCCESS_URL
            ?? `${process.env.FRONTEND_URL ?? 'http://localhost:5173'}/upload?billing=success&session_id={CHECKOUT_SESSION_ID}`,
        stripeCancelUrl: process.env.STRIPE_CANCEL_URL
            ?? `${process.env.FRONTEND_URL ?? 'http://localhost:5173'}/upload?billing=canceled`,
        adminEmails: parseCsv(process.env.ORIGIN_ADMIN_EMAILS),
    },
    studio: {
        workerAuthToken: process.env.STUDIO_WORKER_AUTH_TOKEN ?? '',
        workers: {
            cogVideoXUrl: process.env.STUDIO_WORKER_COGVIDEOX_URL ?? '',
            hunyuanVideoUrl: process.env.STUDIO_WORKER_HUNYUAN_URL ?? '',
            animateDiffUrl: process.env.STUDIO_WORKER_ANIMATEDIFF_URL ?? '',
        },
    },
    abigail: {
        tenantId: process.env.ABIGAIL_TENANT_ID ?? 'origin-web',
        apiKey: process.env.ABIGAIL_API_KEY ?? '',
        maxRetentionDays: parseIntOr(process.env.ABIGAIL_MAX_RETENTION_DAYS, 365),
        hardDeleteGraceDays: parseIntOr(process.env.ABIGAIL_HARD_DELETE_GRACE_DAYS, 30),
        minImportanceToStore: Math.max(0, Math.min(1, parseFloatOr(process.env.ABIGAIL_MIN_IMPORTANCE_TO_STORE, 0.42))),
        blockedSensitiveKeywords: parseCsv(process.env.ABIGAIL_BLOCKED_SENSITIVE_KEYWORDS
            ?? 'medical diagnosis,mental health,religion,political affiliation,sexual orientation,government id,passport,ssn,credit card,password,bank account'),
        anonymizationSalt: process.env.ABIGAIL_ANONYMIZATION_SALT ?? 'origin-abigail-anon',
    },
};
function assertRuntimeConfig() {
    const isProduction = exports.config.nodeEnv === 'production';
    const isCi = isTruthy(process.env.CI);
    if (!exports.config.database.usePrisma) {
        if (isProduction || isCi) {
            throw new Error('USE_PRISMA=1 is required for production/CI startup.');
        }
        return;
    }
    const databaseUrl = (process.env.DATABASE_URL ?? '').trim();
    if (!databaseUrl) {
        throw new Error('DATABASE_URL is required when USE_PRISMA=1.');
    }
    if (isProduction && exports.config.storage.driver === 's3') {
        const { bucket, accessKey, secretKey } = exports.config.storage.s3;
        if (!bucket || !accessKey || !secretKey) {
            throw new Error('S3_BUCKET, S3_ACCESS_KEY, and S3_SECRET_KEY are required when STORAGE_DRIVER=s3.');
        }
    }
}
//# sourceMappingURL=config.js.map