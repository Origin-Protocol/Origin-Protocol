"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ORIGIN_FINGERPRINT_MARKER = exports.ORIGIN_VERIFY_MARKER = void 0;
exports.extractMarkerJson = extractMarkerJson;
exports.extractFingerprintContentHash = extractFingerprintContentHash;
exports.appendOriginFingerprintMetadata = appendOriginFingerprintMetadata;
exports.appendOriginVerificationMetadata = appendOriginVerificationMetadata;
exports.hasBlockingOriginReasons = hasBlockingOriginReasons;
exports.hasRevocationOrConflictReasons = hasRevocationOrConflictReasons;
exports.buildSyntheticFingerprint = buildSyntheticFingerprint;
exports.verifyCreatorUploadAuthenticity = verifyCreatorUploadAuthenticity;
const crypto_1 = __importDefault(require("crypto"));
const originService_1 = require("./originService");
exports.ORIGIN_VERIFY_MARKER = '[origin_verification]';
exports.ORIGIN_FINGERPRINT_MARKER = '[origin_fingerprint]';
function normalizeToken(value) {
    const normalized = (value ?? '').trim().toLowerCase();
    return normalized.length > 0 ? normalized : null;
}
function extractMarkerJson(description, marker) {
    if (!description)
        return null;
    const markerIndex = description.lastIndexOf(marker);
    if (markerIndex < 0)
        return null;
    const encoded = description.slice(markerIndex + marker.length).trim();
    if (!encoded)
        return null;
    try {
        return JSON.parse(encoded);
    }
    catch {
        return null;
    }
}
function extractFingerprintContentHash(description) {
    const parsed = extractMarkerJson(description, exports.ORIGIN_FINGERPRINT_MARKER);
    return normalizeToken(parsed?.contentHash);
}
function appendOriginFingerprintMetadata(description, payload) {
    const encoded = JSON.stringify({
        algorithm: 'sha256',
        contentHash: payload.contentHash,
        ownerCreatorId: payload.ownerCreatorId,
        stampedAt: new Date().toISOString(),
    });
    const base = (description ?? '').trim();
    return base
        ? `${base}\n\n${exports.ORIGIN_FINGERPRINT_MARKER}${encoded}`
        : `${exports.ORIGIN_FINGERPRINT_MARKER}${encoded}`;
}
function appendOriginVerificationMetadata(description, verifyResult) {
    const markerIndex = (description ?? '').indexOf(exports.ORIGIN_VERIFY_MARKER);
    const clean = markerIndex >= 0
        ? (description ?? '').slice(0, markerIndex).trim()
        : (description ?? '').trim();
    const payload = {
        checkedAt: new Date().toISOString(),
        reasons: verifyResult.reasons,
    };
    const encoded = JSON.stringify(payload);
    return clean
        ? `${clean}\n\n${exports.ORIGIN_VERIFY_MARKER}${encoded}`
        : `${exports.ORIGIN_VERIFY_MARKER}${encoded}`;
}
function hasBlockingOriginReasons(result) {
    const blockingCodes = new Set([
        'asset_revoked',
        'key_revoked',
        'creator_revoked',
        'signature_invalid',
        'fingerprint_mismatch',
        'asset_id_collision',
    ]);
    return result.reasons.some((reason) => {
        const code = reason.code?.toLowerCase?.() ?? '';
        if (blockingCodes.has(code))
            return true;
        return code.includes('revok') || code.includes('mismatch') || code.includes('invalid') || code.includes('collision');
    });
}
function hasRevocationOrConflictReasons(reasons) {
    const list = reasons ?? [];
    return list.some((reason) => {
        const code = (reason.code ?? '').toLowerCase();
        return code.includes('revok') || code.includes('invalid') || code.includes('mismatch') || code.includes('collision');
    });
}
function buildSyntheticFingerprint(videoId, videoUrl) {
    return crypto_1.default.createHash('sha256').update(`${videoId}:${videoUrl}`).digest('hex');
}
async function verifyCreatorUploadAuthenticity(params) {
    let verifyResult = null;
    const allowKeyFallback = params.allowKeyFallback !== false;
    const sourceLabel = params.sourceLabel ?? 'upload verification';
    const hasBundleAndHash = Boolean(normalizeToken(params.assetId) && normalizeToken(params.contentHash));
    if (hasBundleAndHash) {
        try {
            verifyResult = await originService_1.originService.verify({
                creatorId: params.creatorId,
                keyId: params.keyId,
                assetId: params.assetId,
                originId: params.originId,
                contentHash: params.contentHash,
            });
            if (verifyResult.ok) {
                return { originVerified: true, verifyResult };
            }
            if (hasBlockingOriginReasons(verifyResult)) {
                return { originVerified: false, verifyResult };
            }
        }
        catch {
            verifyResult = {
                ok: false,
                reasons: [
                    {
                        code: 'ledger_unreachable',
                        severity: 'critical',
                        message: `Origin ledger could not be reached during ${sourceLabel}`,
                        platformAction: allowKeyFallback ? 'allow_key_auth_fallback' : 'retry_later',
                        creatorAction: 'Retry verification later if this persists.',
                    },
                ],
            };
        }
    }
    if (allowKeyFallback) {
        try {
            const keyStatus = await originService_1.originService.keyStatus(params.creatorId, params.keyId);
            if (keyStatus.ok && keyStatus.keyStatus === 'active') {
                const reasons = [
                    ...(verifyResult?.reasons ?? []),
                    {
                        code: 'creator_key_active_auto_verified',
                        severity: 'info',
                        message: 'Auto-verified: creator key is active on Origin node network.',
                        platformAction: 'mark_verified',
                        creatorAction: 'No action needed.',
                    },
                ];
                return {
                    originVerified: true,
                    verifyResult: {
                        ok: true,
                        reasons,
                    },
                };
            }
            if (keyStatus.ok && keyStatus.keyStatus && keyStatus.keyStatus !== 'active') {
                const reasons = [
                    ...(verifyResult?.reasons ?? []),
                    {
                        code: 'creator_key_inactive',
                        severity: 'critical',
                        message: `Creator key status is ${keyStatus.keyStatus}; upload cannot be auto-verified.`,
                        platformAction: 'keep_unverified',
                        creatorAction: 'Rotate/reactivate your Origin creator key, then retry verification.',
                    },
                ];
                return {
                    originVerified: false,
                    verifyResult: {
                        ok: false,
                        reasons,
                    },
                };
            }
        }
        catch {
            // fall through to return prior verification outcome
        }
    }
    return {
        originVerified: Boolean(verifyResult?.ok),
        verifyResult,
    };
}
//# sourceMappingURL=videoVerificationService.js.map