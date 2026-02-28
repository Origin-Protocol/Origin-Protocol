import { OriginReason, OriginVerifyResult } from '../types';
export declare const ORIGIN_VERIFY_MARKER = "[origin_verification]";
export declare const ORIGIN_FINGERPRINT_MARKER = "[origin_fingerprint]";
export declare function extractMarkerJson<T>(description: string | null | undefined, marker: string): T | null;
export declare function extractFingerprintContentHash(description: string | null | undefined): string | null;
export declare function appendOriginFingerprintMetadata(description: string | null | undefined, payload: {
    contentHash: string;
    ownerCreatorId: string;
}): string;
export declare function appendOriginVerificationMetadata(description: string | null | undefined, verifyResult: OriginVerifyResult): string;
export declare function hasBlockingOriginReasons(result: OriginVerifyResult): boolean;
export declare function hasRevocationOrConflictReasons(reasons: OriginReason[] | undefined | null): boolean;
export declare function buildSyntheticFingerprint(videoId: string, videoUrl: string): string;
export declare function verifyCreatorUploadAuthenticity(params: {
    creatorId: string;
    keyId: string;
    assetId?: string | null;
    originId?: string;
    contentHash?: string | null;
    allowKeyFallback?: boolean;
    sourceLabel?: string;
}): Promise<{
    originVerified: boolean;
    verifyResult: OriginVerifyResult | null;
}>;
//# sourceMappingURL=videoVerificationService.d.ts.map