# Origin Social — Backend Server

Node.js + TypeScript REST API that acts as the single control-plane for:
- the web **social-media** creator app
- the **mobile** React Native app (Android & iOS)
- the Origin Protocol ledger for content-ownership verification

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/register` | Create a new user account |
| POST | `/api/auth/login` | Obtain a JWT token |
| GET | `/api/users/:id` | Get a public user profile |
| PATCH | `/api/users/me` | Update the authenticated user's profile |
| GET | `/api/feed` | Paginated public video feed |
| POST | `/api/videos` | Upload a video (multipart/form-data) |
| GET | `/api/videos/:id` | Get a single video |
| DELETE | `/api/videos/:id` | Delete the creator's own video |
| POST | `/api/videos/:id/like` | Like / unlike a video |
| POST | `/api/videos/:id/comments` | Post a comment |
| GET | `/api/videos/:id/comments` | List comments on a video |
| POST | `/api/origin/verify` | Verify an Origin Protocol bundle |
| GET | `/api/origin/key-status` | Check a creator key status |

## Getting started

```bash
cp .env.example .env   # fill in values
npm install
npm run dev            # starts on http://localhost:4000
```

## Running tests

```bash
npm test
```
