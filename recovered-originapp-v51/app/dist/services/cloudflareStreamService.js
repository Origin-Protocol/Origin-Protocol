"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cloudflareStreamService = void 0;
const errorHandler_1 = require("../middleware/errorHandler");
const config_1 = require("../config");
function assertCloudflareConfigured() {
    if (!config_1.config.cloudflareStream.apiToken || !config_1.config.cloudflareStream.accountId) {
        throw new errorHandler_1.HttpError(503, 'Cloudflare Stream is not configured on the server');
    }
}
function cloudflareApi(path) {
    return `https://api.cloudflare.com/client/v4/accounts/${config_1.config.cloudflareStream.accountId}/stream${path}`;
}
function getPlaybackBase() {
    const subdomain = config_1.config.cloudflareStream.subdomain.trim();
    return subdomain ? `https://${subdomain}` : 'https://videodelivery.net';
}
async function parseCloudflareResponse(res) {
    const body = (await res.json().catch(() => ({})));
    if (!res.ok || !body.success || !body.result) {
        const reason = body.errors?.[0]?.message ?? `Cloudflare request failed (${res.status})`;
        throw new errorHandler_1.HttpError(502, reason);
    }
    return body.result;
}
exports.cloudflareStreamService = {
    isConfigured() {
        return Boolean(config_1.config.cloudflareStream.apiToken && config_1.config.cloudflareStream.accountId);
    },
    async createDirectUpload(params) {
        assertCloudflareConfigured();
        const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
        const res = await fetch(cloudflareApi('/direct_upload'), {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${config_1.config.cloudflareStream.apiToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                maxDurationSeconds: 900,
                expiry: expiresAt,
                requireSignedURLs: false,
                meta: {
                    creatorId: params.creatorId,
                    title: params.title,
                },
            }),
        });
        return parseCloudflareResponse(res);
    },
    async getStreamDetails(uid) {
        assertCloudflareConfigured();
        const res = await fetch(cloudflareApi(`/${uid}`), {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${config_1.config.cloudflareStream.apiToken}`,
            },
        });
        return parseCloudflareResponse(res);
    },
    buildPlaybackUrl(uid) {
        return `${getPlaybackBase()}/${uid}/manifest/video.m3u8`;
    },
    buildThumbnailUrl(uid) {
        return `${getPlaybackBase()}/${uid}/thumbnails/thumbnail.jpg?time=1s`;
    },
};
//# sourceMappingURL=cloudflareStreamService.js.map