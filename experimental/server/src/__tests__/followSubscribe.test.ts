/**
 * Tests for Follow / Subscribe routes.
 *
 * Uses the in-memory store directly (no real HTTP server) by importing app
 * with supertest-like patterns — we call route handlers through the Express app.
 */
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import app, { server } from '../index';
import { db } from '../models/store';
import { config } from '../config';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeToken(userId: string): string {
  return jwt.sign({ sub: userId }, config.jwt.secret, { expiresIn: '1h' });
}

function createUser(overrides: Partial<{ id: string; email: string; username: string }> = {}) {
  const id = overrides.id ?? uuidv4();
  const user = {
    id,
    username: overrides.username ?? `user_${id.slice(0, 6)}`,
    email: overrides.email ?? `${id.slice(0, 6)}@example.com`,
    displayName: 'Test User',
    avatarUrl: null,
    bio: null,
    creatorKeyId: null,
    createdAt: new Date().toISOString(),
    passwordHash: 'hash',
  };
  db.users.set(id, user);
  return user;
}

// ---------------------------------------------------------------------------
// Reset store between tests
// ---------------------------------------------------------------------------
afterAll(() => server.close());

beforeEach(() => {
  db.users.clear();
  db.followers.clear();
  db.subscriptions.clear();
  db.entitlements.clear();
  db.creatorSettings.clear();
  db.exclusiveContent.clear();
});

// ---------------------------------------------------------------------------
// Follow routes
// ---------------------------------------------------------------------------
describe('Follow routes', () => {
  it('follows a creator', async () => {
    const fan = createUser();
    const creator = createUser();

    const res = await request(app)
      .post(`/api/follow/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    expect(res.status).toBe(201);
    expect(res.body.followed).toBe(true);
  });

  it('returns 200 when already following', async () => {
    const fan = createUser();
    const creator = createUser();

    await request(app)
      .post(`/api/follow/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    const res = await request(app)
      .post(`/api/follow/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    expect(res.status).toBe(200);
    expect(res.body.followed).toBe(true);
  });

  it('rejects self-follow', async () => {
    const user = createUser();

    const res = await request(app)
      .post(`/api/follow/${user.id}`)
      .set('Authorization', `Bearer ${makeToken(user.id)}`);

    expect(res.status).toBe(400);
  });

  it('returns 404 when following non-existent creator', async () => {
    const fan = createUser();

    const res = await request(app)
      .post(`/api/follow/non-existent-id`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    expect(res.status).toBe(404);
  });

  it('unfollows a creator', async () => {
    const fan = createUser();
    const creator = createUser();

    await request(app)
      .post(`/api/follow/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    const res = await request(app)
      .delete(`/api/follow/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    expect(res.status).toBe(200);
    expect(res.body.followed).toBe(false);
  });

  it('GET /api/follow/:creatorId returns follow status', async () => {
    const fan = createUser();
    const creator = createUser();

    let res = await request(app)
      .get(`/api/follow/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);
    expect(res.body.followed).toBe(false);

    await request(app)
      .post(`/api/follow/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    res = await request(app)
      .get(`/api/follow/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);
    expect(res.body.followed).toBe(true);
  });

  it('requires auth', async () => {
    const creator = createUser();
    const res = await request(app).post(`/api/follow/${creator.id}`);
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// Creator subscription settings
// ---------------------------------------------------------------------------
describe('Creator subscription settings', () => {
  it('creator can enable subscriptions', async () => {
    const creator = createUser();

    const res = await request(app)
      .post('/api/creator/subscriptions/settings')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({ subscriptionsEnabled: true, basicPriceCents: 599, superFanPriceCents: 1299 });

    expect(res.status).toBe(200);
    expect(res.body.settings.subscriptionsEnabled).toBe(true);
    expect(res.body.settings.basicPriceCents).toBe(599);
    expect(res.body.settings.superFanPriceCents).toBe(1299);
  });

  it('validates price is at least $1', async () => {
    const creator = createUser();

    const res = await request(app)
      .post('/api/creator/subscriptions/settings')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({ basicPriceCents: 50 }); // below min

    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Public tier listing
// ---------------------------------------------------------------------------
describe('GET /api/creator/:id/subscriptions', () => {
  it('returns disabled when creator has no settings', async () => {
    const creator = createUser();
    const res = await request(app).get(`/api/creator/${creator.id}/subscriptions`);
    expect(res.status).toBe(200);
    expect(res.body.subscriptionsEnabled).toBe(false);
  });

  it('returns tiers when enabled', async () => {
    const creator = createUser();

    await request(app)
      .post('/api/creator/subscriptions/settings')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({ subscriptionsEnabled: true, basicPriceCents: 499, superFanPriceCents: 999 });

    const res = await request(app).get(`/api/creator/${creator.id}/subscriptions`);
    expect(res.status).toBe(200);
    expect(res.body.tiers).toHaveLength(2);
    expect(res.body.tiers[0].tier).toBe(1);
    expect(res.body.tiers[1].tier).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Subscribe route (dev/test mode without real Stripe)
// ---------------------------------------------------------------------------
describe('POST /api/subscribe/:creatorId', () => {
  it('subscribes fan at tier 1', async () => {
    const fan = createUser();
    const creator = createUser();

    // Enable subscriptions
    await request(app)
      .post('/api/creator/subscriptions/settings')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({ subscriptionsEnabled: true });

    const res = await request(app)
      .post(`/api/subscribe/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`)
      .send({ tier: 1 });

    expect(res.status).toBe(201);
    expect(res.body.subscription.tier).toBe(1);
    expect(res.body.subscription.active).toBe(true);
  });

  it('rejects duplicate subscription at same or lower tier', async () => {
    const fan = createUser();
    const creator = createUser();

    await request(app)
      .post('/api/creator/subscriptions/settings')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({ subscriptionsEnabled: true });

    await request(app)
      .post(`/api/subscribe/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`)
      .send({ tier: 2 });

    const res = await request(app)
      .post(`/api/subscribe/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`)
      .send({ tier: 1 });

    expect(res.status).toBe(409);
  });

  it('rejects when subscriptions disabled', async () => {
    const fan = createUser();
    const creator = createUser();

    const res = await request(app)
      .post(`/api/subscribe/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`)
      .send({ tier: 1 });

    expect(res.status).toBe(400);
  });

  it('rejects self-subscribe', async () => {
    const user = createUser();

    await request(app)
      .post('/api/creator/subscriptions/settings')
      .set('Authorization', `Bearer ${makeToken(user.id)}`)
      .send({ subscriptionsEnabled: true });

    const res = await request(app)
      .post(`/api/subscribe/${user.id}`)
      .set('Authorization', `Bearer ${makeToken(user.id)}`)
      .send({ tier: 1 });

    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Upgrade route
// ---------------------------------------------------------------------------
describe('POST /api/upgrade/:creatorId', () => {
  it('upgrades tier 1 to tier 2', async () => {
    const fan = createUser();
    const creator = createUser();

    await request(app)
      .post('/api/creator/subscriptions/settings')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({ subscriptionsEnabled: true });

    await request(app)
      .post(`/api/subscribe/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`)
      .send({ tier: 1 });

    const res = await request(app)
      .post(`/api/upgrade/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`)
      .send({ tier: 2 });

    expect(res.status).toBe(200);
    expect(res.body.subscription.tier).toBe(2);
  });

  it('rejects upgrade without an existing subscription', async () => {
    const fan = createUser();
    const creator = createUser();

    await request(app)
      .post('/api/creator/subscriptions/settings')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({ subscriptionsEnabled: true });

    const res = await request(app)
      .post(`/api/upgrade/${creator.id}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`)
      .send({ tier: 2 });

    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Exclusive content routes
// ---------------------------------------------------------------------------
describe('Exclusive content routes', () => {
  it('creator can publish exclusive content', async () => {
    const creator = createUser();

    const res = await request(app)
      .post('/api/content')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({
        title: 'Behind the Scenes',
        contentUrl: 'https://example.com/video.mp4',
        requiredTier: 2,
      });

    expect(res.status).toBe(201);
    expect(res.body.content.requiredTier).toBe(2);
  });

  it('creator can access their own content', async () => {
    const creator = createUser();

    const createRes = await request(app)
      .post('/api/content')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({
        title: 'Private Video',
        contentUrl: 'https://example.com/private.mp4',
        requiredTier: 1,
      });

    const contentId = createRes.body.content.id;

    const res = await request(app)
      .get(`/api/content/${contentId}`)
      .set('Authorization', `Bearer ${makeToken(creator.id)}`);

    expect(res.status).toBe(200);
  });

  it('fan with correct tier can access content', async () => {
    const fan = createUser();
    const creator = createUser();

    // Setup entitlement directly
    db.entitlements.set(`${fan.id}:${creator.id}`, {
      userId: fan.id,
      creatorId: creator.id,
      tier: 2,
      active: true,
      expiresAt: null,
    });

    const createRes = await request(app)
      .post('/api/content')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({
        title: 'Exclusive Video',
        contentUrl: 'https://example.com/exclusive.mp4',
        requiredTier: 2,
      });

    const contentId = createRes.body.content.id;

    const res = await request(app)
      .get(`/api/content/${contentId}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    expect(res.status).toBe(200);
    expect(res.body.content.title).toBe('Exclusive Video');
  });

  it('fan without subscription cannot access content', async () => {
    const fan = createUser();
    const creator = createUser();

    const createRes = await request(app)
      .post('/api/content')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({
        title: 'Super Fan Content',
        contentUrl: 'https://example.com/superfan.mp4',
        requiredTier: 2,
      });

    const contentId = createRes.body.content.id;

    const res = await request(app)
      .get(`/api/content/${contentId}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    expect(res.status).toBe(403);
  });

  it('fan with tier 1 cannot access tier 2 content', async () => {
    const fan = createUser();
    const creator = createUser();

    db.entitlements.set(`${fan.id}:${creator.id}`, {
      userId: fan.id,
      creatorId: creator.id,
      tier: 1,
      active: true,
      expiresAt: null,
    });

    const createRes = await request(app)
      .post('/api/content')
      .set('Authorization', `Bearer ${makeToken(creator.id)}`)
      .send({
        title: 'Super Fan Only',
        contentUrl: 'https://example.com/superfan-only.mp4',
        requiredTier: 2,
      });

    const contentId = createRes.body.content.id;

    const res = await request(app)
      .get(`/api/content/${contentId}`)
      .set('Authorization', `Bearer ${makeToken(fan.id)}`);

    expect(res.status).toBe(403);
  });
});
