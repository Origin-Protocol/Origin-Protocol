# Origin Social — Web Creator App

React + TypeScript web application that lets content creators:
- Browse a TikTok-style video feed
- Upload videos with optional **Origin Protocol** ownership proofs
- View and edit their creator profile

## Getting started

```bash
npm install
npm run dev     # http://localhost:3000
```

The app proxies `/api` and `/uploads` requests to the backend server running
on `http://localhost:4000`. Start the server first (see `../server/README.md`).

## Build for production

```bash
npm run build   # output in dist/
```
