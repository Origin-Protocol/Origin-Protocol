"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runRemoteStudioInference = runRemoteStudioInference;
const config_1 = require("../../../config");
function asNumber(value, fallback) {
    const parsed = typeof value === 'number' ? value : Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
}
function toBuffer(payload) {
    if (payload.outputBase64) {
        return Buffer.from(payload.outputBase64, 'base64');
    }
    return Buffer.from(payload.outputText ?? '', 'utf8');
}
async function runRemoteStudioInference(params) {
    const endpoint = params.endpoint.trim();
    if (!endpoint)
        return null;
    const startedAt = Date.now();
    const headers = {
        'Content-Type': 'application/json',
    };
    if (config_1.config.studio.workerAuthToken.trim()) {
        headers.Authorization = `Bearer ${config_1.config.studio.workerAuthToken.trim()}`;
    }
    const response = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(params.payload),
    });
    if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(`${params.adapterName} worker request failed (${response.status})${text ? `: ${text}` : ''}`);
    }
    const body = await response.json();
    const outputBuffer = toBuffer(body);
    const outputMimeType = (body.outputMimeType ?? '').trim() || 'video/mp4';
    const outputExtension = (body.outputExtension ?? '').trim() || 'mp4';
    return {
        outputBuffer,
        outputMimeType,
        outputExtension,
        durationSeconds: Math.max(1, Math.round(asNumber(body.durationSeconds, params.fallbackDurationSeconds))),
        estimatedCostUsd: Math.max(0, asNumber(body.estimatedCostUsd, params.fallbackCostUsd)),
        trace: {
            adapter: params.adapterName,
            inferenceMs: Date.now() - startedAt,
            notes: ['remote worker inference', ...(body.notes ?? [])],
        },
    };
}
//# sourceMappingURL=inferenceGateway.js.map