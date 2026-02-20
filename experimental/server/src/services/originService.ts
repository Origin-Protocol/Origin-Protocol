import { config } from '../config';
import { OriginVerifyResult } from '../types';

/**
 * Thin client for the Origin Protocol ledger API (Python/tools/full_node_service.py).
 * Mirrors the contract defined in Python/docs/Platform_API_Contract_v1.md.
 */
export const originService = {
  /**
   * Verify that an asset is authentic and not revoked according to the ledger.
   */
  async verify(params: {
    creatorId: string;
    keyId: string;
    assetId: string;
    originId?: string;
    contentHash: string;
  }): Promise<OriginVerifyResult> {
    const body = {
      creator_id: params.creatorId,
      key_id: params.keyId,
      asset_id: params.assetId,
      origin_id: params.originId,
      content_hash: params.contentHash,
      platform_id: config.origin.platformId,
    };

    const res = await fetch(`${config.origin.ledgerUrl}/v1/ledger/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      return {
        ok: false,
        reasons: [
          {
            code: 'ledger_error',
            severity: 'critical',
            message: `Ledger returned HTTP ${res.status}`,
            platformAction: 'reject_upload',
            creatorAction: 'Contact support.',
          },
        ],
      };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await res.json();
    return {
      ok: data.ok,
      reasons: (data.reasons ?? []).map(
        (r: {
          code: string;
          severity: string;
          message: string;
          platform_action: string;
          creator_action: string;
        }) => ({
          code: r.code,
          severity: r.severity,
          message: r.message,
          platformAction: r.platform_action,
          creatorAction: r.creator_action,
        })
      ),
    };
  },

  /**
   * Check whether a creator's signing key is active.
   */
  async keyStatus(
    creatorId: string,
    keyId: string
  ): Promise<{ ok: boolean; keyStatus: string | null; reasons: unknown[] }> {
    const url = new URL(`${config.origin.ledgerUrl}/v1/ledger/key-status`);
    url.searchParams.set('creator_id', creatorId);
    url.searchParams.set('key_id', keyId);

    const res = await fetch(url.toString());
    if (!res.ok) {
      return { ok: false, keyStatus: null, reasons: [] };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const data: any = await res.json();
    return {
      ok: data.ok,
      keyStatus: data.key_status ?? null,
      reasons: data.reasons ?? [],
    };
  },
};
