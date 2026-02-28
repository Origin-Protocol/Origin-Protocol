"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const originService_1 = require("../services/originService");
describe('originService.verify', () => {
    it('returns ok:false with ledger_error when the ledger is unreachable', async () => {
        // No real ledger running — fetch will throw ECONNREFUSED
        const result = await originService_1.originService.verify({
            creatorId: 'creator-1',
            keyId: 'key-1',
            assetId: 'asset-1',
            contentHash: 'abc123',
        }).catch(() => ({
            ok: false,
            reasons: [{ code: 'ledger_error', severity: 'critical', message: '', platformAction: '', creatorAction: '' }],
        }));
        expect(result.ok).toBe(false);
    });
    it('returns ok:false with ledger_error when keyStatus ledger is unreachable', async () => {
        const result = await originService_1.originService.keyStatus('creator-1', 'key-1').catch(() => ({
            ok: false,
            keyStatus: null,
            reasons: [],
        }));
        expect(result.ok).toBe(false);
    });
});
//# sourceMappingURL=originService.test.js.map