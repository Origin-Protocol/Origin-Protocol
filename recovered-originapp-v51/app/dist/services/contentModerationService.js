"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.contentModerationService = void 0;
const config_1 = require("../config");
function containsBlockedTerms(text) {
    const normalized = text.toLowerCase();
    const matches = [];
    for (const term of config_1.config.moderation.blockedKeywords) {
        const candidate = term.trim().toLowerCase();
        if (!candidate)
            continue;
        if (normalized.includes(candidate)) {
            matches.push(candidate);
        }
    }
    return [...new Set(matches)];
}
function moderationToken() {
    return config_1.config.moderation.cloudflareApiToken || config_1.config.cloudflareStream.apiToken;
}
function hasCloudflareWorkerModeration() {
    return Boolean(config_1.config.moderation.cloudflareApiUrl && moderationToken());
}
function hasCloudflareAiModeration() {
    return Boolean(config_1.config.moderation.cloudflareAccountId && moderationToken());
}
function hasCloudflareModeration() {
    return hasCloudflareWorkerModeration() || hasCloudflareAiModeration();
}
async function callCloudflareWorkerModeration(input) {
    const endpoint = config_1.config.moderation.cloudflareApiUrl;
    const token = moderationToken();
    const retries = Math.max(1, config_1.config.moderation.retries + 1);
    for (let attempt = 1; attempt <= retries; attempt += 1) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), Math.max(1000, config_1.config.moderation.timeoutMs));
        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    creatorId: input.creatorId,
                    source: input.source,
                    title: input.title ?? '',
                    description: input.description ?? '',
                    videoUrl: input.videoUrl ?? null,
                    streamUid: input.streamUid ?? null,
                }),
                signal: controller.signal,
            });
            if (res.status >= 500 || res.status === 408 || res.status === 429) {
                if (attempt < retries)
                    continue;
                throw new Error(`Cloudflare moderation unavailable (${res.status})`);
            }
            if (!res.ok) {
                throw new Error(`Cloudflare moderation request failed (${res.status})`);
            }
            const payload = (await res.json().catch(() => ({})));
            const allow = payload.allow ?? !payload.blocked;
            return {
                allowed: Boolean(allow),
                provider: 'cloudflare-worker',
                reason: payload.reason,
                categories: payload.categories,
            };
        }
        catch (error) {
            if (attempt >= retries) {
                throw error;
            }
        }
        finally {
            clearTimeout(timeout);
        }
    }
    throw new Error('Cloudflare moderation unavailable');
}
function inferUnsafeCategories(raw) {
    const text = raw.toLowerCase();
    const categories = new Set();
    if (/(sexual|sex|adult|porn|nsfw|escort|prostitution)/.test(text)) {
        categories.add('adult-sexual-content');
    }
    return [...categories];
}
function isAiBlocked(raw, flagged) {
    if (flagged === true)
        return true;
    const text = raw.toLowerCase();
    if (text.includes('"allow":false') || text.includes('"blocked":true'))
        return true;
    if (text.includes('unsafe') && /(sexual|sex|adult|porn|nsfw)/.test(text))
        return true;
    return false;
}
async function callCloudflareAiModeration(input) {
    const accountId = config_1.config.moderation.cloudflareAccountId;
    const token = moderationToken();
    const model = config_1.config.moderation.cloudflareModel;
    const endpoint = `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/run/${model}`;
    const retries = Math.max(1, config_1.config.moderation.retries + 1);
    for (let attempt = 1; attempt <= retries; attempt += 1) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), Math.max(1000, config_1.config.moderation.timeoutMs));
        try {
            const payloadForModel = {
                messages: [
                    {
                        role: 'system',
                        content: 'Classify platform publish safety. Block sexual/adult-industry content. Respond concise JSON: {"allow":boolean,"reason":string,"categories":[string]}.',
                    },
                    {
                        role: 'user',
                        content: `source=${input.source}\ntitle=${input.title ?? ''}\ndescription=${input.description ?? ''}`,
                    },
                ],
            };
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payloadForModel),
                signal: controller.signal,
            });
            if (res.status >= 500 || res.status === 408 || res.status === 429) {
                if (attempt < retries)
                    continue;
                throw new Error(`Cloudflare AI moderation unavailable (${res.status})`);
            }
            if (!res.ok) {
                throw new Error(`Cloudflare AI moderation request failed (${res.status})`);
            }
            const envelope = (await res.json().catch(() => ({})));
            const raw = JSON.stringify(envelope.result ?? envelope);
            const blocked = isAiBlocked(raw, envelope.result?.flagged);
            return {
                allowed: !blocked,
                provider: 'cloudflare-ai',
                reason: blocked ? 'Blocked by Cloudflare AI moderation policy' : 'Cloudflare AI moderation passed',
                categories: envelope.result?.categories ?? inferUnsafeCategories(raw),
            };
        }
        catch (error) {
            if (attempt >= retries) {
                throw error;
            }
        }
        finally {
            clearTimeout(timeout);
        }
    }
    throw new Error('Cloudflare AI moderation unavailable');
}
exports.contentModerationService = {
    async evaluate(input) {
        const text = `${input.title ?? ''}\n${input.description ?? ''}`.trim();
        const blockedTerms = containsBlockedTerms(text);
        if (blockedTerms.length > 0) {
            return {
                allowed: false,
                provider: 'local-keywords',
                reason: 'Content contains restricted adult terms',
                matchedTerms: blockedTerms,
                categories: ['adult-sexual-content'],
            };
        }
        if (!hasCloudflareModeration()) {
            return { allowed: true, provider: 'none' };
        }
        if (hasCloudflareWorkerModeration()) {
            return callCloudflareWorkerModeration(input);
        }
        if (hasCloudflareAiModeration()) {
            return callCloudflareAiModeration(input);
        }
        return { allowed: true, provider: 'none' };
    },
};
//# sourceMappingURL=contentModerationService.js.map