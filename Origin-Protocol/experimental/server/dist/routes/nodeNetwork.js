"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const express_1 = require("express");
const zod_1 = require("zod");
const router = (0, express_1.Router)();
const ATTESTATION_LOG_PATH = path_1.default.resolve(process.cwd(), '.data', 'attestations.jsonl');
const attestationSchema = zod_1.z.object({
    asset_id: zod_1.z.string().min(1),
    media_hash: zod_1.z.string().min(1),
    manifest_hash: zod_1.z.string().min(1),
    creator_public_key: zod_1.z.string().min(1),
    sealed_at: zod_1.z.coerce.number().int(),
    lineage: zod_1.z
        .object({
        type: zod_1.z.string().min(1),
        parents: zod_1.z.array(zod_1.z.string()).default([]),
    })
        .default({ type: 'original', parents: [] }),
    signature: zod_1.z.string().min(1),
});
function ensureDataDir() {
    const dataDir = path_1.default.dirname(ATTESTATION_LOG_PATH);
    if (!fs_1.default.existsSync(dataDir)) {
        fs_1.default.mkdirSync(dataDir, { recursive: true });
    }
}
function loadAttestations() {
    if (!fs_1.default.existsSync(ATTESTATION_LOG_PATH))
        return [];
    const lines = fs_1.default.readFileSync(ATTESTATION_LOG_PATH, 'utf-8').split(/\r?\n/).filter(Boolean);
    const items = [];
    for (const line of lines) {
        try {
            items.push(JSON.parse(line));
        }
        catch {
            // ignore malformed rows
        }
    }
    return items;
}
function appendAttestation(row) {
    ensureDataDir();
    fs_1.default.appendFileSync(ATTESTATION_LOG_PATH, `${JSON.stringify(row)}\n`, 'utf-8');
}
// Light -> Full: submit attestation
router.post('/attestations', (req, res) => {
    const parsed = attestationSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const entries = loadAttestations();
    const nextIndex = (entries.at(-1)?.index ?? 0) + 1;
    const body = parsed.data;
    const row = {
        index: nextIndex,
        asset_id: body.asset_id,
        media_hash: body.media_hash,
        manifest_hash: body.manifest_hash,
        creator_public_key: body.creator_public_key,
        sealed_at: body.sealed_at,
        lineage: body.lineage,
        signature: body.signature,
        received_at: new Date().toISOString(),
    };
    appendAttestation(row);
    res.status(201).json({ ok: true, index: row.index });
});
// Light -> Full: query attestations by media hash or asset id
router.get('/attestations', (req, res) => {
    const mediaHash = String(req.query.media_hash ?? '').trim();
    const assetId = String(req.query.asset_id ?? '').trim();
    const entries = loadAttestations();
    const items = entries.filter((entry) => {
        if (mediaHash && entry.media_hash !== mediaHash)
            return false;
        if (assetId && entry.asset_id !== assetId)
            return false;
        return true;
    });
    res.json({ items, total: items.length });
});
// Full <-> Full: append-only replication stream
router.get('/log', (req, res) => {
    const since = Number(req.query.since ?? 0);
    const cursor = Number.isFinite(since) && since > 0 ? Math.floor(since) : 0;
    const entries = loadAttestations();
    const items = entries.filter((entry) => entry.index > cursor);
    res.json({
        since: cursor,
        latest: entries.at(-1)?.index ?? 0,
        items,
        total: items.length,
    });
});
exports.default = router;
//# sourceMappingURL=nodeNetwork.js.map