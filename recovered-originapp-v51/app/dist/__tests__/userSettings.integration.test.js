"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
process.env.USE_PRISMA = '0';
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'test-secret';
process.env.STORAGE_LOCAL_DIR = process.env.STORAGE_LOCAL_DIR ?? './uploads';
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const index_1 = require("../index");
describe('User settings integration', () => {
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
    it('returns defaults, applies settings patch, and bridges personal profile fields', async () => {
        const seed = Date.now();
        const account = await createUserAndToken({
            username: `settings_user_${seed}`,
            email: `settings_user_${seed}@example.com`,
            password: 'TestPass123!',
            displayName: 'Settings User',
        });
        const defaultsRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            headers: { Authorization: `Bearer ${account.token}` },
        });
        expect(defaultsRes.status).toBe(200);
        const defaultsBody = await defaultsRes.json();
        expect(defaultsBody.settings.userId).toBe(account.userId);
        expect(defaultsBody.settings.personalInformation.username).toBe(`settings_user_${seed}`);
        expect(defaultsBody.settings.personalInformation.displayName).toBe('Settings User');
        expect(defaultsBody.settings.devicesSessions.activeSessions.length).toBeGreaterThan(0);
        const updatedUsername = `settings_renamed_${seed}`;
        const patchRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${account.token}`,
            },
            body: JSON.stringify({
                personalInformation: {
                    username: updatedUsername,
                    displayName: 'Renamed Settings User',
                    bio: 'Updated from settings patch',
                    profilePhoto: 'https://example.com/avatar.png',
                },
                preferences: {
                    notificationMode: 'minimal',
                    language: 'en-US',
                },
            }),
        });
        expect(patchRes.status).toBe(200);
        const patchBody = await patchRes.json();
        expect(patchBody.settings.personalInformation.username).toBe(updatedUsername);
        expect(patchBody.settings.personalInformation.displayName).toBe('Renamed Settings User');
        expect(patchBody.settings.personalInformation.bio).toBe('Updated from settings patch');
        expect(patchBody.settings.personalInformation.profilePhoto).toBe('https://example.com/avatar.png');
        expect(patchBody.settings.preferences.notificationMode).toBe('minimal');
        expect(patchBody.settings.preferences.language).toBe('en-US');
        const byUsernameRes = await fetch(`${baseUrl}/api/users/by-username/${updatedUsername}`);
        expect(byUsernameRes.status).toBe(200);
        const byUsername = await byUsernameRes.json();
        expect(byUsername.user.username).toBe(updatedUsername);
        expect(byUsername.user.displayName).toBe('Renamed Settings User');
        expect(byUsername.user.bio).toBe('Updated from settings patch');
        expect(byUsername.user.avatarUrl).toBe('https://example.com/avatar.png');
    });
    it('rejects settings patch when username conflicts with another account', async () => {
        const seed = Date.now();
        const firstUsername = `sca_${seed}`;
        const secondUsername = `scb_${seed}`;
        const first = await createUserAndToken({
            username: firstUsername,
            email: `${firstUsername}@example.com`,
            password: 'TestPass123!',
            displayName: 'Conflict A',
        });
        const second = await createUserAndToken({
            username: secondUsername,
            email: `${secondUsername}@example.com`,
            password: 'TestPass123!',
            displayName: 'Conflict B',
        });
        const conflictRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${second.token}`,
            },
            body: JSON.stringify({
                personalInformation: {
                    username: firstUsername,
                },
            }),
        });
        expect(conflictRes.status).toBe(409);
        const firstCheck = await fetch(`${baseUrl}/api/users/by-username/${firstUsername}`);
        expect(firstCheck.status).toBe(200);
        const firstBody = await firstCheck.json();
        expect(firstBody.user.id).toBe(first.userId);
    });
    it('revokes a non-current session, exports payload, and recreates defaults after delete', async () => {
        const seed = Date.now();
        const account = await createUserAndToken({
            username: `settings_manage_${seed}`,
            email: `settings_manage_${seed}@example.com`,
            password: 'TestPass123!',
            displayName: 'Settings Manage',
        });
        const hydrateRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            headers: { Authorization: `Bearer ${account.token}` },
        });
        expect(hydrateRes.status).toBe(200);
        const secondSessionId = `session-manual-${seed}`;
        const appendSessionRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${account.token}`,
            },
            body: JSON.stringify({
                devicesSessions: {
                    activeSessions: [
                        {
                            id: secondSessionId,
                            deviceName: 'Other Browser',
                            location: 'Remote',
                            ipAddress: '10.0.0.2',
                            lastSeenAt: new Date().toISOString(),
                            current: false,
                        },
                    ],
                },
            }),
        });
        expect(appendSessionRes.status).toBe(200);
        const revokeRes = await fetch(`${baseUrl}/api/users/me/settings/revoke-session`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${account.token}`,
            },
            body: JSON.stringify({ sessionId: secondSessionId }),
        });
        expect(revokeRes.status).toBe(200);
        const revokeBody = await revokeRes.json();
        expect(revokeBody.settings.devicesSessions.activeSessions.some((session) => session.id === secondSessionId)).toBe(false);
        expect(revokeBody.settings.devicesSessions.deviceList.some((session) => session.id === secondSessionId)).toBe(false);
        const exportRes = await fetch(`${baseUrl}/api/users/me/settings/export`, {
            headers: { Authorization: `Bearer ${account.token}` },
        });
        expect(exportRes.status).toBe(200);
        const exportBody = await exportRes.json();
        expect(exportBody.settings.userId).toBe(account.userId);
        expect(exportBody.exportedAt).toBeTruthy();
        const deleteRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${account.token}` },
        });
        expect(deleteRes.status).toBe(204);
        const afterDeleteRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            headers: { Authorization: `Bearer ${account.token}` },
        });
        expect(afterDeleteRes.status).toBe(200);
        const afterDelete = await afterDeleteRes.json();
        expect(afterDelete.settings.devicesSessions.activeSessions.length).toBeGreaterThan(0);
        expect(afterDelete.settings.devicesSessions.activeSessions.some((session) => session.id === secondSessionId)).toBe(false);
    });
    it('requires auth for all /api/users/me/settings endpoints', async () => {
        const getRes = await fetch(`${baseUrl}/api/users/me/settings`);
        expect(getRes.status).toBe(401);
        const patchRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ preferences: { theme: 'dark' } }),
        });
        expect(patchRes.status).toBe(401);
        const revokeRes = await fetch(`${baseUrl}/api/users/me/settings/revoke-session`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sessionId: 'any' }),
        });
        expect(revokeRes.status).toBe(401);
        const exportRes = await fetch(`${baseUrl}/api/users/me/settings/export`);
        expect(exportRes.status).toBe(401);
        const deleteRes = await fetch(`${baseUrl}/api/users/me/settings`, {
            method: 'DELETE',
        });
        expect(deleteRes.status).toBe(401);
    });
});
//# sourceMappingURL=userSettings.integration.test.js.map