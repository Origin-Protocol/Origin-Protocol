# Origin Server Restore Plan (from `recovered-originapp-v51`)

## Snapshot summary

Current server state is effectively a skeleton:
- `src/services/messagingStore.ts` only
- minimal `package.json` and `tsconfig.json`

Recovered deploy artifact (`recovered-originapp-v51`) contains:
- compiled backend under `app/dist`
- Prisma schema and seed under `prisma/`
- a richer `package.json` with full runtime deps

## High-impact gaps (current vs recovered)

### Missing route surface
Recovered `dist/routes/*` includes:
- `auth`, `users`, `videos`, `feed`, `discover`, `origin`
- `membership`, `admin`, `messaging`, `studio`, `live`, `abigail`, `nodeNetwork`

### Missing service surface
Recovered `dist/services/*` includes:
- `cloudflareStreamService`, `originService`, `videoVerificationService`, `syncHistoryStore`
- `adminStore`, `liveStore`, `abigailMemoryStore`, `recommendationService`, `userSettingsStore`
- studio stack (`studio/*`, adapters, queue, credits, usage, object storage)

### Infra / middleware drift
Recovered app uses middleware and security stack not present in current package:
- `express-async-errors`, `helmet`, `morgan`, `express-rate-limit`
- Stripe and Prisma integration
- optional S3 + Cloudflare integrations

## Restore strategy (safe order)

1. **Create a working branch and backup current server**
   - copy current `experimental/server` to `experimental/server.backup.<timestamp>`

2. **Rebuild source tree from recovered `dist` using source maps**
   - recovered files include `*.js.map`; use them to reconstruct TS layout under `src/`
   - prioritize these first:
     - `index`
     - `config`
     - `middleware/auth`, `middleware/errorHandler`
     - all `routes/*`
     - all `services/*`
     - `repositories/*`, `models/*`, `types/*`

3. **Align package/runtime config**
   - merge recovered `package.json` scripts + deps into current server
   - update `tsconfig.json` to match CommonJS emit expectations if needed by reconstructed code

4. **Restore Prisma**
   - keep recovered `prisma/schema.prisma` and `prisma/seed.js`
   - run generate + schema validation before starting app

5. **Boot and endpoint validation**
   - run build/start
   - verify critical paths:
     - `/api/videos`, `/api/videos/sealed`, `/api/videos/cloudflare/*`
     - `/api/origin/*`
     - `/api/membership/*`
     - `/api/messaging/*`
     - `/api/studio/*`

6. **Data/secret parity check before deploy**
   - verify env keys for Prisma, Stripe, Cloudflare, ingest key, allowed origins

## Recommended execution mode

Because recovered payload is compiled JS, fastest reliable path is:
- use recovered `dist` immediately as temporary runtime baseline
- reconstruct TypeScript incrementally from source maps
- switch runtime back to rebuilt TS once parity tests pass

## Files compared in this analysis

- Current server:
  - `Origin-Protocol/experimental/server/package.json`
  - `Origin-Protocol/experimental/server/tsconfig.json`
  - `Origin-Protocol/experimental/server/src/services/messagingStore.ts`

- Recovered:
  - `recovered-originapp-v51/package.json`
  - `recovered-originapp-v51/prisma/schema.prisma`
  - `recovered-originapp-v51/app/dist/index.js`
  - `recovered-originapp-v51/app/dist/**/*`
