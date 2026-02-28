# Origin Social — Backend Server

Node.js + TypeScript REST API that acts as the single control-plane for:
- the web **social-media** creator app
- the **mobile** React Native app (Android & iOS)
- the Origin Protocol ledger for content-ownership verification

By default, development data persists to `.data/store.json` (users, videos,
comments, likes) so restarts do not wipe local state.

Messaging state is persisted in `messaging.json` and supports overrides:

- `ORIGIN_DATA_DIR` (directory for file-backed stores; e.g. `/data` on Fly)
- `ORIGIN_MESSAGING_STORE_FILE` (optional full path override for messaging store)

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Create a new user account |
| POST | `/api/auth/login` | Obtain a JWT token |
| GET | `/api/users/:id` | Get a public user profile |
| GET | `/api/users/:id/videos` | List videos for one creator |
| PATCH | `/api/users/me` | Update the authenticated user's profile |
| GET | `/api/feed` | Paginated public video feed |
| POST | `/api/videos` | Upload a video (multipart/form-data) |
| POST | `/api/videos/sealed` | Publish a pre-sealed video record (Creator Tool bridge) |
| POST | `/api/videos/cloudflare/direct-upload` | Create Cloudflare Stream direct upload URL (auth required) |
| POST | `/api/videos/cloudflare/finalize` | Finalize Cloudflare Stream upload into feed record (auth required) |
| GET | `/api/videos/:id` | Get a single video |
| DELETE | `/api/videos/:id` | Delete the creator's own video |
| POST | `/api/videos/:id/like` | Like / unlike a video |
| POST | `/api/videos/:id/comments` | Post a comment |
| GET | `/api/videos/:id/comments` | List comments on a video |
| POST | `/api/origin/verify` | Verify an Origin Protocol bundle |
| GET | `/api/origin/key-status` | Check a creator key status |

### Abigail memory/personalization endpoints

These are mounted at root for dedicated Abigail service compatibility:

- `POST /chat`
- `POST /memory/update`
- `GET /memory/snapshot?user_id=...`
- `GET /recommendations?user_id=...`
- `POST /memory/ingest`
- `GET /memory/context?user_id=...`
- `POST /memory/forget`
- `GET /memory/export?user_id=...`

See [docs/ABIGAIL_MEMORY_API.md](docs/ABIGAIL_MEMORY_API.md) for full contract and policy controls.

`POST /api/videos/sealed` supports either:
- `Authorization: Bearer <jwt>` (preferred), or
- `X-Origin-Ingest-Key: <key>` when `ORIGIN_INGEST_API_KEY` is configured.

## Cloudflare Stream (optional)

To enable direct-to-Cloudflare mobile uploads and playback URLs:

```bash
CLOUDFLARE_STREAM_API_TOKEN=...
CLOUDFLARE_ACCOUNT_ID=...
CLOUDFLARE_STREAM_SUBDOMAIN=customer-xxxxx.cloudflarestream.com
```

When configured, mobile upload first attempts Cloudflare direct upload and
falls back to legacy multipart `/api/videos` if Cloudflare is unavailable.

## Storage backends

Video multipart upload supports two storage drivers:

- `local` (default): saves files under `STORAGE_LOCAL_DIR` and serves `/uploads/*`
- `s3`: scaffolded configuration path for upcoming object-storage rollout (not enabled for multipart writes yet)

```bash
STORAGE_DRIVER=local
STORAGE_LOCAL_DIR=./uploads

# or
STORAGE_DRIVER=s3
S3_BUCKET=origin-social-videos
S3_REGION=us-east-1
S3_ACCESS_KEY=...
S3_SECRET_KEY=...
S3_ENDPOINT=   # optional for S3-compatible providers
```

## Getting started

```bash
cp .env.example .env   # fill in values
npm install
npm run dev            # starts on http://localhost:4000
```

## PostgreSQL scaffold (Prisma)

The project now includes an initial Prisma schema at [prisma/schema.prisma](prisma/schema.prisma).

Set `USE_PRISMA=1` in `.env` to enable the gradual Prisma-backed path for auth,
users, feed, and video routes.

```bash
# set DATABASE_URL in .env first
npm run prisma:generate
npm run prisma:migrate -- --name init
npm run prisma:seed
```

By default (`USE_PRISMA=0`), routes use the local persisted dev store (`.data/store.json`).
When enabled, Prisma-backed code paths are used for core auth/user/video/feed flows.

If `prisma db push` returns `P1001` for a Supabase host, use the Supabase
**pooler** connection string (IPv4-friendly) from the project dashboard instead
of the direct `db.<project-ref>.supabase.co:5432` URL.

## Supabase hardening (RLS + policies)

Use the SQL scripts in [supabase/001_rls_policies.sql](supabase/001_rls_policies.sql)
and [supabase/002_verification_checks.sql](supabase/002_verification_checks.sql).

1. Open Supabase SQL Editor for your project.
2. Run `001_rls_policies.sql` once.
3. Run `002_verification_checks.sql` and confirm expected rows are returned.

Notes:
- The `User` base table includes `passwordHash`; direct read access is restricted.
- A safe public profile projection is provided via `public.user_profiles`.
- Current app auth issues its own JWT (`sub = userId`). If you want clients to
	query Supabase directly under RLS, align client auth with Supabase Auth so
	`auth.uid()` resolves as expected.

## Fly.io deployment

This server now includes:
- [fly.toml](fly.toml)
- [Dockerfile](Dockerfile)
- [.dockerignore](.dockerignore)

From this folder, deploy with:

```bash
fly auth login
fly apps create <your-unique-app-name>
fly deploy
```

Before first deploy, set required runtime secrets:

```bash
fly secrets set \
	DATABASE_URL="<supabase-pooler-url>" \
	JWT_SECRET="<strong-random-secret>" \
	ORIGIN_INGEST_API_KEY="<strong-random-secret>" \
	ALLOWED_ORIGINS="https://<your-web-domain>"
```

If you use Cloudflare Stream, also set:

```bash
fly secrets set \
	CLOUDFLARE_STREAM_API_TOKEN="<token>" \
	CLOUDFLARE_ACCOUNT_ID="<account-id>" \
	CLOUDFLARE_STREAM_SUBDOMAIN="<customer-subdomain>"
```

Useful commands:

```bash
fly status
fly logs
fly ssh console
```

To keep file-backed data (including messaging history) across restarts/deploys,
provision and mount a Fly volume, then deploy with `ORIGIN_DATA_DIR=/data`.

```bash
fly volumes create origin_data --region iad --size 3
fly deploy
```

## Running tests

```bash
npm test
```
