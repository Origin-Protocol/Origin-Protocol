# Experimental — Origin Social

A TikTok-style social video platform with built-in creator-ownership protection
powered by the [Origin Protocol](../Python/README.md).

## Components

| Directory | Description |
|-----------|-------------|
| [`server/`](./server/README.md) | Node.js + TypeScript REST API — the single control-plane for every client |
| [`social-media/`](./social-media/README.md) | React + TypeScript web app for content creators |
| [`mobile/`](./mobile/README.md) | React Native app — runs on both Android and iOS |

## How they connect

```
┌─────────────────────────────────────────┐
│          experimental/server            │
│  (Express · JWT · Origin Protocol SDK)  │
└────────────┬──────────────┬─────────────┘
             │              │
    ┌────────▼──────┐  ┌────▼────────────┐
    │ social-media  │  │    mobile       │
    │  (React/TS)   │  │ (React Native)  │
    │  Web creator  │  │  Android + iOS  │
    └───────────────┘  └─────────────────┘
```

The server exposes a single REST API that all clients consume.  Every video
upload is verified through the Origin Protocol ledger before it is stored, so
creator ownership is cryptographically established at upload time.

## Quick start

```bash
# 1 — start the backend
cd server && npm install && npm run dev

# 2 — start the web creator app (new terminal)
cd social-media && npm install && npm run dev

# 3 — start the mobile app (new terminal, requires Expo CLI)
cd mobile && npm install && npx expo start
```

## Environment variables

Copy `server/.env.example` to `server/.env` and fill in the values before
starting the server.
