"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
process.env.USE_PRISMA = '0';
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'test-secret';
process.env.STORAGE_LOCAL_DIR = process.env.STORAGE_LOCAL_DIR ?? './uploads';
process.env.ORIGIN_ADMIN_EMAILS = process.env.ORIGIN_ADMIN_EMAILS ?? 'admin_verify@example.com';
process.env.ORIGIN_LEDGER_URL = process.env.ORIGIN_LEDGER_URL ?? 'http://127.0.0.1:19050';
process.env.CLOUDFLARE_STREAM_API_TOKEN = '';
process.env.CLOUDFLARE_ACCOUNT_ID = '';
process.env.CLOUDFLARE_STREAM_SUBDOMAIN = '';
process.env.CLOUDFLARE_MODERATION_API_URL = '';
process.env.CLOUDFLARE_MODERATION_API_TOKEN = '';
process.env.CLOUDFLARE_MODERATION_ACCOUNT_ID = '';
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const node_http_1 = __importDefault(require("node:http"));
const index_1 = require("../index");
const store_1 = require("../models/store");
describe('API integration smoke', () => {
    const dataDir = node_path_1.default.resolve('.data');
    const app = (0, index_1.createApp)();
    let baseUrl = '';
    let server;
    let ledgerServer;
    const verifyScenarioByAssetId = new Map();
    const keyStatusByKeyId = new Map();
    beforeAll(async () => {
        node_fs_1.default.rmSync(dataDir, { recursive: true, force: true });
        store_1.db.users.clear();
        store_1.db.videos.clear();
        store_1.db.comments.clear();
        store_1.db.likes.clear();
        ledgerServer = node_http_1.default.createServer((req, res) => {
            if (!req.url) {
                res.statusCode = 404;
                res.end();
                return;
            }
            if (req.method === 'POST' && req.url === '/v1/ledger/verify') {
                let raw = '';
                req.on('data', (chunk) => { raw += chunk.toString(); });
                req.on('end', () => {
                    const body = JSON.parse(raw || '{}');
                    const scenario = verifyScenarioByAssetId.get(body.asset_id ?? '') ?? {
                        ok: false,
                        reasons: [
                            {
                                code: 'verification_unknown',
                                severity: 'warning',
                                message: 'No mock scenario for this asset',
                                platform_action: 'keep_unverified',
                                creator_action: 'Retry later',
                            },
                        ],
                    };
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify(scenario));
                });
                return;
            }
            if (req.method === 'GET' && req.url.startsWith('/v1/ledger/key-status')) {
                const url = new URL(req.url, 'http://127.0.0.1:19050');
                const keyId = url.searchParams.get('key_id') ?? '';
                const keyStatus = keyStatusByKeyId.get(keyId) ?? 'inactive';
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ ok: true, key_status: keyStatus, reasons: [] }));
                return;
            }
            res.statusCode = 404;
            res.end();
        });
        await new Promise((resolve) => {
            ledgerServer.listen(19050, '127.0.0.1', () => resolve());
        });
        server = app.listen(0);
        await new Promise((resolve) => {
            server.on('listening', () => resolve());
        });
        const address = server.address();
        baseUrl = `http://127.0.0.1:${address.port}`;
    });
    afterAll(async () => {
        await new Promise((resolve, reject) => {
            server.close((err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
        await new Promise((resolve, reject) => {
            ledgerServer.close((err) => {
                if (err)
                    reject(err);
                else
                    resolve();
            });
        });
    });
    async function createUserAndToken(params) {
        const registerRes = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...params, acceptTerms: true }),
        });
        expect(registerRes.status).toBe(201);
        const reg = await registerRes.json();
        const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: params.email, password: params.password }),
        });
        expect(loginRes.status).toBe(200);
        const login = await loginRes.json();
        return { token: login.token, userId: reg.user.id };
    }
    it('supports auth/feed/profile/video/comment/like flow', async () => {
        const username = 'int_user_flow';
        const email = 'int_user_flow@example.com';
        const password = 'TestPass123!';
        const registerRes = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, displayName: 'Integration User', acceptTerms: true }),
        });
        expect(registerRes.status).toBe(201);
        const registerBody = await registerRes.json();
        expect(registerBody.token).toBeTruthy();
        const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        expect(loginRes.status).toBe(200);
        const loginBody = await loginRes.json();
        expect(loginBody.token).toBeTruthy();
        const token = loginBody.token;
        const patchMeRes = await fetch(`${baseUrl}/api/users/me`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ bio: 'integration-bio' }),
        });
        expect(patchMeRes.status).toBe(200);
        const sealedRes = await fetch(`${baseUrl}/api/videos/sealed`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
                title: 'Integration Video',
                description: 'Smoke test',
                videoUrl: 'https://example.com/video.mp4',
            }),
        });
        expect(sealedRes.status).toBe(201);
        const sealedBody = await sealedRes.json();
        const videoId = sealedBody.video.id;
        expect(videoId).toBeTruthy();
        const feedRes = await fetch(`${baseUrl}/api/feed?page=1&pageSize=10`, {
            headers: { Authorization: `Bearer ${token}` },
        });
        expect(feedRes.status).toBe(200);
        const feedBody = await feedRes.json();
        expect(feedBody.items.some((item) => item.id === videoId)).toBe(true);
        const likeRes = await fetch(`${baseUrl}/api/videos/${videoId}/like`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` },
        });
        expect(likeRes.status).toBe(200);
        const likeBody = await likeRes.json();
        expect(likeBody.liked).toBe(true);
        const commentRes = await fetch(`${baseUrl}/api/videos/${videoId}/comments`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ text: 'integration comment' }),
        });
        expect(commentRes.status).toBe(201);
        const commentsRes = await fetch(`${baseUrl}/api/videos/${videoId}/comments`);
        expect(commentsRes.status).toBe(200);
        const commentsBody = await commentsRes.json();
        expect(commentsBody.comments.some((comment) => comment.text === 'integration comment')).toBe(true);
    });
    it('returns an auth/config error for cloudflare direct-upload when not configured', async () => {
        const username = 'int_cf_flow';
        const email = 'int_cf_flow@example.com';
        const password = 'TestPass123!';
        const registerRes = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, displayName: 'CF User', acceptTerms: true }),
        });
        expect(registerRes.status).toBe(201);
        const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        expect(loginRes.status).toBe(200);
        const loginBody = await loginRes.json();
        expect(loginBody.token).toBeTruthy();
        const cfRes = await fetch(`${baseUrl}/api/videos/cloudflare/direct-upload`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${loginBody.token}`,
            },
            body: JSON.stringify({ title: 'CF smoke' }),
        });
        expect([502, 503]).toContain(cfRes.status);
    });
    it('rejects sealed publish when Origin evidence is incomplete', async () => {
        const username = 'int_sealed_incomplete';
        const email = 'int_sealed_incomplete@example.com';
        const password = 'TestPass123!';
        const registerRes = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, displayName: 'Sealed Incomplete', acceptTerms: true }),
        });
        expect(registerRes.status).toBe(201);
        const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        const loginBody = await loginRes.json();
        const sealedRes = await fetch(`${baseUrl}/api/videos/sealed`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${loginBody.token}`,
            },
            body: JSON.stringify({
                title: 'Bad sealed payload',
                videoUrl: 'https://example.com/incomplete.mp4',
                originBundleId: 'clip.origin.zip',
                assetId: 'asset-only',
            }),
        });
        expect(sealedRes.status).toBe(400);
    });
    it('rejects sealed publish when Origin verification fails', async () => {
        const username = 'int_sealed_verify';
        const email = 'int_sealed_verify@example.com';
        const password = 'TestPass123!';
        const registerRes = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password, displayName: 'Sealed Verify', acceptTerms: true }),
        });
        expect(registerRes.status).toBe(201);
        const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        const loginBody = await loginRes.json();
        const sealedRes = await fetch(`${baseUrl}/api/videos/sealed`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${loginBody.token}`,
            },
            body: JSON.stringify({
                title: 'Unverifiable sealed payload',
                videoUrl: 'https://example.com/unverifiable.mp4',
                originBundleId: 'clip.origin.zip',
                assetId: 'asset-1',
                keyId: 'key-1',
                contentHash: 'hash-1',
            }),
        });
        expect(sealedRes.status).toBe(422);
    });
    it('admin verify-now succeeds when ledger verify is ok', async () => {
        const admin = await createUserAndToken({
            username: 'admin_verify_user',
            email: 'admin_verify@example.com',
            password: 'TestPass123!',
            displayName: 'Admin Verify',
        });
        const creator = await createUserAndToken({
            username: 'creator_verify_user',
            email: 'creator_verify@example.com',
            password: 'TestPass123!',
            displayName: 'Creator Verify',
        });
        const creatorUser = store_1.db.users.get(creator.userId);
        expect(creatorUser).toBeTruthy();
        store_1.db.users.set(creator.userId, { ...creatorUser, creatorKeyId: 'key-success' });
        verifyScenarioByAssetId.set('asset-success', {
            ok: true,
            reasons: [
                {
                    code: 'ledger_verified',
                    severity: 'info',
                    message: 'Ledger verified',
                    platform_action: 'mark_verified',
                    creator_action: 'none',
                },
            ],
        });
        store_1.db.videos.set('video-success', {
            id: 'video-success',
            creatorId: creator.userId,
            title: 'Video Success',
            description: '[origin_fingerprint]{"contentHash":"hash-success"}',
            videoUrl: 'https://example.com/video-success.mp4',
            thumbnailUrl: null,
            duration: null,
            likeCount: 0,
            commentCount: 0,
            viewCount: 0,
            originBundleId: 'asset-success',
            originVerified: false,
            createdAt: new Date().toISOString(),
        });
        const verifyNowRes = await fetch(`${baseUrl}/api/admin/videos/video-success/verify-now`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${admin.token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({}),
        });
        expect(verifyNowRes.status).toBe(200);
        const body = await verifyNowRes.json();
        expect(body.status).toBe('verified');
        expect(body.ok).toBe(true);
        expect(store_1.db.videos.get('video-success')?.originVerified).toBe(true);
    });
    it('admin verify-now supports active-key fallback when ledger verify fails', async () => {
        const adminLogin = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'admin_verify@example.com', password: 'TestPass123!' }),
        });
        const admin = await adminLogin.json();
        const creator = await createUserAndToken({
            username: 'creator_fallback_user',
            email: 'creator_fallback@example.com',
            password: 'TestPass123!',
            displayName: 'Creator Fallback',
        });
        const creatorUser = store_1.db.users.get(creator.userId);
        store_1.db.users.set(creator.userId, { ...creatorUser, creatorKeyId: 'key-fallback' });
        verifyScenarioByAssetId.set('asset-fallback', {
            ok: false,
            reasons: [
                {
                    code: 'ledger_error',
                    severity: 'warning',
                    message: 'Ledger temporary error',
                    platform_action: 'allow_key_auth_fallback',
                    creator_action: 'retry',
                },
            ],
        });
        keyStatusByKeyId.set('key-fallback', 'active');
        store_1.db.videos.set('video-fallback', {
            id: 'video-fallback',
            creatorId: creator.userId,
            title: 'Video Fallback',
            description: '[origin_fingerprint]{"contentHash":"hash-fallback"}',
            videoUrl: 'https://example.com/video-fallback.mp4',
            thumbnailUrl: null,
            duration: null,
            likeCount: 0,
            commentCount: 0,
            viewCount: 0,
            originBundleId: 'asset-fallback',
            originVerified: false,
            createdAt: new Date().toISOString(),
        });
        const res = await fetch(`${baseUrl}/api/admin/videos/video-fallback/verify-now`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${admin.token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ allowKeyFallback: true }),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.ok).toBe(true);
        expect(body.reasons.some((reason) => reason.code === 'creator_key_active_auto_verified')).toBe(true);
        expect(store_1.db.videos.get('video-fallback')?.originVerified).toBe(true);
    });
    it('revocation re-check marks verified videos invalid when revoked', async () => {
        const adminLogin = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'admin_verify@example.com', password: 'TestPass123!' }),
        });
        const admin = await adminLogin.json();
        const creator = await createUserAndToken({
            username: 'creator_revoke_user',
            email: 'creator_revoke@example.com',
            password: 'TestPass123!',
            displayName: 'Creator Revoke',
        });
        const creatorUser = store_1.db.users.get(creator.userId);
        store_1.db.users.set(creator.userId, { ...creatorUser, creatorKeyId: 'key-revoke' });
        verifyScenarioByAssetId.set('asset-revoked', {
            ok: false,
            reasons: [
                {
                    code: 'asset_revoked',
                    severity: 'critical',
                    message: 'Asset has been revoked',
                    platform_action: 'mark_unverified',
                    creator_action: 're-seal asset',
                },
            ],
        });
        keyStatusByKeyId.set('key-revoke', 'active');
        store_1.db.videos.set('video-revoked', {
            id: 'video-revoked',
            creatorId: creator.userId,
            title: 'Video Revoked',
            description: '[origin_fingerprint]{"contentHash":"hash-revoked"}',
            videoUrl: 'https://example.com/video-revoked.mp4',
            thumbnailUrl: null,
            duration: null,
            likeCount: 0,
            commentCount: 0,
            viewCount: 0,
            originBundleId: 'asset-revoked',
            originVerified: true,
            createdAt: new Date().toISOString(),
        });
        const res = await fetch(`${baseUrl}/api/admin/videos/recheck-revocations`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${admin.token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ onlyVerified: true, limit: 50 }),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.revokedOrInvalid).toBeGreaterThanOrEqual(1);
        expect(store_1.db.videos.get('video-revoked')?.originVerified).toBe(false);
    });
    it('bulk verify endpoint updates multiple unverified videos', async () => {
        const adminLogin = await fetch(`${baseUrl}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'admin_verify@example.com', password: 'TestPass123!' }),
        });
        const admin = await adminLogin.json();
        const creator = await createUserAndToken({
            username: 'creator_bulk_user',
            email: 'creator_bulk@example.com',
            password: 'TestPass123!',
            displayName: 'Creator Bulk',
        });
        const creatorUser = store_1.db.users.get(creator.userId);
        store_1.db.users.set(creator.userId, { ...creatorUser, creatorKeyId: 'key-bulk' });
        verifyScenarioByAssetId.set('asset-bulk-1', {
            ok: true,
            reasons: [
                {
                    code: 'ledger_verified',
                    severity: 'info',
                    message: 'Verified',
                    platform_action: 'mark_verified',
                    creator_action: 'none',
                },
            ],
        });
        verifyScenarioByAssetId.set('asset-bulk-2', {
            ok: true,
            reasons: [
                {
                    code: 'ledger_verified',
                    severity: 'info',
                    message: 'Verified',
                    platform_action: 'mark_verified',
                    creator_action: 'none',
                },
            ],
        });
        store_1.db.videos.set('video-bulk-1', {
            id: 'video-bulk-1',
            creatorId: creator.userId,
            title: 'Video Bulk 1',
            description: '[origin_fingerprint]{"contentHash":"hash-bulk-1"}',
            videoUrl: 'https://example.com/video-bulk-1.mp4',
            thumbnailUrl: null,
            duration: null,
            likeCount: 0,
            commentCount: 0,
            viewCount: 0,
            originBundleId: 'asset-bulk-1',
            originVerified: false,
            createdAt: new Date().toISOString(),
        });
        store_1.db.videos.set('video-bulk-2', {
            id: 'video-bulk-2',
            creatorId: creator.userId,
            title: 'Video Bulk 2',
            description: '[origin_fingerprint]{"contentHash":"hash-bulk-2"}',
            videoUrl: 'https://example.com/video-bulk-2.mp4',
            thumbnailUrl: null,
            duration: null,
            likeCount: 0,
            commentCount: 0,
            viewCount: 0,
            originBundleId: 'asset-bulk-2',
            originVerified: false,
            createdAt: new Date().toISOString(),
        });
        const res = await fetch(`${baseUrl}/api/admin/videos/verify-bulk`, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${admin.token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ unverifiedOnly: true, creatorId: creator.userId, limit: 20 }),
        });
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.processed).toBeGreaterThanOrEqual(2);
        expect(body.verified).toBeGreaterThanOrEqual(2);
        expect(body.failed).toBe(0);
        expect(store_1.db.videos.get('video-bulk-1')?.originVerified).toBe(true);
        expect(store_1.db.videos.get('video-bulk-2')?.originVerified).toBe(true);
    });
});
//# sourceMappingURL=api.integration.test.js.map