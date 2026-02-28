import { OriginVerifyResult } from '../types';
/**
 * Thin client for the Origin Protocol ledger API (Python/tools/full_node_service.py).
 * Mirrors the contract defined in Python/docs/Platform_API_Contract_v1.md.
 */
export declare const originService: {
    /**
     * Verify that an asset is authentic and not revoked according to the ledger.
     */
    verify(params: {
        creatorId: string;
        keyId: string;
        assetId: string;
        originId?: string;
        contentHash: string;
    }): Promise<OriginVerifyResult>;
    /**
     * Check whether a creator's signing key is active.
     */
    keyStatus(creatorId: string, keyId: string): Promise<{
        ok: boolean;
        keyStatus: string | null;
        reasons: unknown[];
    }>;
};
//# sourceMappingURL=originService.d.ts.map