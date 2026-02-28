"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
process.env.USE_PRISMA = '0';
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'test-secret';
process.env.STORAGE_LOCAL_DIR = process.env.STORAGE_LOCAL_DIR ?? './uploads';
process.env.ABIGAIL_TENANT_ID = process.env.ABIGAIL_TENANT_ID ?? 'origin-web';
process.env.ABIGAIL_API_KEY = '';
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const index_1 = require("../index");
describe('Abigail memory integration', () => {
    const dataDir = node_path_1.default.resolve('.data');
    const app = (0, index_1.createApp)();
    let baseUrl = '';
    let server;
    beforeAll(async () => {
        node_fs_1.default.rmSync(dataDir, { recursive: true, force: true });
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
    });
    it('ingests chat and retrieves personalized context', async () => {
        const userId = `abigail-user-${Date.now()}`;
        const chatRes = await fetch(`${baseUrl}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-tenant-id': 'origin-web',
            },
            body: JSON.stringify({
                user_id: userId,
                message: 'I want to grow my channel this quarter and I prefer brief direct responses.',
            }),
        });
        expect(chatRes.status).toBe(200);
        const chatBody = await chatRes.json();
        expect(chatBody.reply).toBeTruthy();
        expect(Array.isArray(chatBody.memory_updates.created)).toBe(true);
        expect(Array.isArray(chatBody.context_bundle)).toBe(true);
        const contextRes = await fetch(`${baseUrl}/memory/context?user_id=${encodeURIComponent(userId)}&query=${encodeURIComponent('goal and response style')}`, {
            headers: {
                'x-tenant-id': 'origin-web',
            },
        });
        expect(contextRes.status).toBe(200);
        const contextBody = await contextRes.json();
        expect(contextBody.profile).toBeTruthy();
        expect(Array.isArray(contextBody.memories)).toBe(true);
        expect(contextBody.memories.length).toBeGreaterThan(0);
        expect(Array.isArray(contextBody.bundle)).toBe(true);
    });
    it('supports forget hook with soft delete and context reduction', async () => {
        const userId = `abigail-forget-${Date.now()}`;
        const seedRes = await fetch(`${baseUrl}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-tenant-id': 'origin-web',
            },
            body: JSON.stringify({
                user_id: userId,
                message: 'I am working on launching a weekly creator newsletter and I like concise plans.',
            }),
        });
        expect(seedRes.status).toBe(200);
        const forgetRes = await fetch(`${baseUrl}/memory/forget`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-tenant-id': 'origin-web',
            },
            body: JSON.stringify({
                user_id: userId,
                hard_delete: false,
            }),
        });
        expect(forgetRes.status).toBe(200);
        const forgetBody = await forgetRes.json();
        expect(forgetBody.ok).toBe(true);
        expect(forgetBody.affectedMemories).toBeGreaterThan(0);
        const contextAfterForgetRes = await fetch(`${baseUrl}/memory/context?user_id=${encodeURIComponent(userId)}`, {
            headers: {
                'x-tenant-id': 'origin-web',
            },
        });
        expect(contextAfterForgetRes.status).toBe(200);
        const contextAfterForget = await contextAfterForgetRes.json();
        expect(Array.isArray(contextAfterForget.memories)).toBe(true);
        expect(contextAfterForget.memories.length).toBe(0);
    });
    it('exports user memory payload for portability', async () => {
        const userId = `abigail-export-${Date.now()}`;
        const chatRes = await fetch(`${baseUrl}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-tenant-id': 'origin-web',
            },
            body: JSON.stringify({
                user_id: userId,
                message: 'I prefer friendly concise replies and I am building a weekly publishing habit.',
            }),
        });
        expect(chatRes.status).toBe(200);
        const exportRes = await fetch(`${baseUrl}/memory/export?user_id=${encodeURIComponent(userId)}`, {
            headers: {
                'x-tenant-id': 'origin-web',
            },
        });
        expect(exportRes.status).toBe(200);
        const exported = await exportRes.json();
        expect(exported.exportedAt).toBeTruthy();
        expect(Array.isArray(exported.memories)).toBe(true);
        expect(Array.isArray(exported.events)).toBe(true);
        expect(exported.memories.some((item) => item.userId === userId)).toBe(true);
    });
    it('anonymizes memory values when forget hook is called with anonymize=true', async () => {
        const userId = `abigail-anon-${Date.now()}`;
        const chatRes = await fetch(`${baseUrl}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-tenant-id': 'origin-web',
            },
            body: JSON.stringify({
                user_id: userId,
                message: 'I prefer direct coaching and I am building a daily writing habit.',
            }),
        });
        expect(chatRes.status).toBe(200);
        const anonymizeRes = await fetch(`${baseUrl}/memory/forget`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-tenant-id': 'origin-web',
            },
            body: JSON.stringify({
                user_id: userId,
                anonymize: true,
                hard_delete: false,
            }),
        });
        expect(anonymizeRes.status).toBe(200);
        const exportRes = await fetch(`${baseUrl}/memory/export?user_id=${encodeURIComponent(userId)}`, {
            headers: {
                'x-tenant-id': 'origin-web',
            },
        });
        expect(exportRes.status).toBe(200);
        const exported = await exportRes.json();
        expect(exported.memories.length).toBeGreaterThan(0);
        expect(exported.memories.every((item) => item.value.startsWith('[anonymized:'))).toBe(true);
        expect(exported.memories.every((item) => item.summary === 'Anonymized memory record')).toBe(true);
        expect(exported.events.every((item) => !item.detail || item.detail === 'Anonymized event detail')).toBe(true);
    });
    it('rejects missing tenant header with contract error', async () => {
        const res = await fetch(`${baseUrl}/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                user_id: `abigail-tenant-${Date.now()}`,
                message: 'hello',
            }),
        });
        expect(res.status).toBe(422);
        const body = await res.json();
        expect(body.error).toContain('x-tenant-id');
    });
});
//# sourceMappingURL=abigail.integration.test.js.map