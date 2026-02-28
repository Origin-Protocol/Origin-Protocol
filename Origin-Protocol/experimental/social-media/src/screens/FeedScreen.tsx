import { useEffect, useState, useCallback, useMemo } from 'react';
import { abigailApi, feedApi, getOrCreateAbigailSessionId, resolveApiAssetUrl } from '../api/client';
import { VideoMeta } from '../types';
import VideoCard from '../components/VideoCard';
import { Link, useLocation } from 'react-router-dom';
import ReelsDesktop from '../components/reels/ReelsDesktop';
import { useAuth } from '../hooks/useAuth';
import {
  getNotificationPermission,
  notifyWithExternalOpen,
  requestBrowserNotificationPermission,
  supportsBrowserNotifications,
} from '../utils/browserNotifications';

type FeedMode = 'cards' | 'reels';
const FEED_MODE_KEY = 'origin_feed_mode_web';
const RECENT_UPLOAD_KEY = 'origin_recent_upload_video';
const ABIGAIL_NOTIFIED_RECS_KEY = 'origin_abigail_notified_recs_v1';

function getInitialMode(): FeedMode {
  if (typeof window === 'undefined') return 'reels';
  const stored = window.localStorage.getItem(FEED_MODE_KEY);
  return stored === 'cards' ? 'cards' : 'reels';
}

function extractHashtags(text: string): string[] {
  const matches = text.match(/#[a-z0-9_]+/gi) ?? [];
  return matches.map((tag) => tag.toLowerCase());
}

function inferTopic(video: VideoMeta): string {
  const text = `${video.title} ${video.description ?? ''}`.toLowerCase();
  if (/music|song|beat|dj|album|rap|sing/.test(text)) return 'music';
  if (/game|gaming|fortnite|roblox|minecraft|fps|stream/.test(text)) return 'gaming';
  if (/cook|recipe|food|kitchen|meal|chef/.test(text)) return 'food';
  if (/travel|trip|city|beach|vacation|flight/.test(text)) return 'travel';
  if (/tech|ai|code|app|software|device|gadget/.test(text)) return 'tech';
  if (/learn|tutorial|class|how to|lesson|tips/.test(text)) return 'education';
  if (/fitness|gym|workout|run|yoga|health/.test(text)) return 'fitness';
  if (/comedy|funny|meme|joke|skit/.test(text)) return 'comedy';
  return 'general';
}

export default function FeedScreen() {
  const { user } = useAuth();
  const location = useLocation();
  const [audience, setAudience] = useState<'all' | 'following'>('all');
  const [contentFilter, setContentFilter] = useState<'all' | 'protected'>('all');
  const [creatorFilter, setCreatorFilter] = useState<string>('all');
  const [topicFilter, setTopicFilter] = useState<string>('all');
  const [hashtagFilter, setHashtagFilter] = useState<string>('all');
  const [videos, setVideos] = useState<VideoMeta[]>([]);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<FeedMode>(getInitialMode);
  const [showFilters, setShowFilters] = useState(false);
  const [abigailItems, setAbigailItems] = useState<Array<{ id: string; title: string; reason: string; kind: 'video' | 'article' | 'task'; href?: string }>>([]);
  const [abigailOffline, setAbigailOffline] = useState(false);
  const [abigailLoading, setAbigailLoading] = useState(false);
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission>(() => getNotificationPermission());

  const notificationStateLabel = !supportsBrowserNotifications()
    ? 'Notifications unsupported'
    : notificationPermission === 'granted'
      ? 'Notifications enabled'
      : notificationPermission === 'denied'
        ? 'Notifications blocked'
        : 'Notifications not enabled';

  const notificationStateColor = !supportsBrowserNotifications()
    ? '#9ca3af'
    : notificationPermission === 'granted'
      ? '#86efac'
      : notificationPermission === 'denied'
        ? '#fca5a5'
        : '#fbbf24';

  function loadNotifiedRecommendationIds(): Set<string> {
    try {
      const raw = window.localStorage.getItem(ABIGAIL_NOTIFIED_RECS_KEY);
      const parsed = raw ? (JSON.parse(raw) as string[]) : [];
      return new Set(Array.isArray(parsed) ? parsed : []);
    } catch {
      return new Set<string>();
    }
  }

  function saveNotifiedRecommendationIds(ids: Set<string>) {
    window.localStorage.setItem(ABIGAIL_NOTIFIED_RECS_KEY, JSON.stringify([...ids].slice(-300)));
  }

  async function refreshAbigailRecommendations() {
    if (!user) return;
    setAbigailLoading(true);
    try {
      const sid = getOrCreateAbigailSessionId(user.id);
      const recs = await abigailApi.recommendations({ userId: user.id, sessionId: sid });
      setAbigailItems(recs.items.slice(0, 3));
      setAbigailOffline(recs.offline);

      if (supportsBrowserNotifications() && Notification.permission === 'granted') {
        const seen = loadNotifiedRecommendationIds();
        const candidate = recs.items.find((item) => !seen.has(item.id));
        if (candidate) {
          const href = recommendationHref(candidate.href);
          const shown = notifyWithExternalOpen({
            title: 'New Abigail recommendation',
            body: `${candidate.title} (${candidate.kind})`,
            href,
            tag: `abigail-rec-${candidate.id}`,
          });
          if (shown) {
            seen.add(candidate.id);
            saveNotifiedRecommendationIds(seen);
          }
        }
      }
    } catch {
      setAbigailItems([]);
      setAbigailOffline(true);
    } finally {
      setAbigailLoading(false);
    }
  }

  useEffect(() => {
    const raw = window.localStorage.getItem(RECENT_UPLOAD_KEY);
    if (!raw) return;
    try {
      const recent = JSON.parse(raw) as VideoMeta;
      setVideos((prev) => {
        if (prev.some((item) => item.id === recent.id)) return prev;
        return [recent, ...prev];
      });
    } finally {
      window.localStorage.removeItem(RECENT_UPLOAD_KEY);
    }
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(FEED_MODE_KEY, mode);
  }, [mode]);

  useEffect(() => {
    setShowFilters(mode === 'cards');
  }, [mode]);

  useEffect(() => {
    if (!user) {
      setAbigailItems([]);
      setAbigailOffline(false);
      return;
    }

    void refreshAbigailRecommendations();
    const timer = window.setInterval(() => {
      void refreshAbigailRecommendations();
    }, 45_000);
    return () => {
      window.clearInterval(timer);
    };
  }, [user?.id]);

  async function enableAbigailAlerts() {
    const permission = await requestBrowserNotificationPermission();
    setNotificationPermission(permission);
  }

  function sendTestAbigailNotification() {
    const shown = notifyWithExternalOpen({
      title: 'Abigail test notification',
      body: 'Click to open Abigail in a new window.',
      href: '/abigail',
      tag: 'abigail-test-notification',
    });
    if (!shown) {
      void enableAbigailAlerts();
    }
  }

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;
    setLoading(true);
    try {
      const data = await feedApi.get(page, 20, 'home');
      setVideos((prev) => {
        const map = new Map<string, VideoMeta>();
        for (const item of prev) map.set(item.id, item);
        for (const item of data.items) map.set(item.id, item);
        return [...map.values()];
      });
      setHasMore(data.hasMore);
      setPage((p) => p + 1);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [loading, hasMore, page]);

  useEffect(() => {
    let cancelled = false;
    async function reloadFeed() {
      setLoading(true);
      setError(null);
      try {
        const data = await feedApi.get(1, 20, 'home');
        if (cancelled) return;
        setVideos(data.items);
        setHasMore(data.hasMore);
        setPage(2);
      } catch (e) {
        if (!cancelled) setError((e as Error).message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void reloadFeed();
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <main style={{ maxWidth: 640, margin: '32px auto', color: '#fff', padding: 12 }}>
        <h2 style={{ marginBottom: 8 }}>Feed unavailable</h2>
        <p style={{ color: '#fca5a5' }}>Error: {error}</p>
        <button onClick={() => window.location.reload()} style={{ padding: '8px 12px', borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff' }}>
          Retry
        </button>
      </main>
    );
  }

  const creatorOptions = useMemo(() => {
    const map = new Map<string, string>();
    for (const item of videos) {
      map.set(item.creatorId, item.creatorDisplayName || item.creatorUsername || 'Unknown creator');
    }
    return [...map.entries()].map(([id, name]) => ({ id, name }));
  }, [videos]);

  const followingCreatorIds = useMemo(() => {
    try {
      const raw = window.localStorage.getItem('origin_creator_subscriptions_v1');
      const parsed = raw ? JSON.parse(raw) as Record<string, boolean> : {};
      return new Set(
        Object.entries(parsed)
          .filter(([, subscribed]) => Boolean(subscribed))
          .map(([creatorId]) => creatorId)
      );
    } catch {
      return new Set<string>();
    }
  }, []);

  const topicOptions = useMemo(() => {
    return [...new Set(videos.map((item) => inferTopic(item)))].sort();
  }, [videos]);

  const topHashtags = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of videos) {
      const tags = extractHashtags(`${item.title} ${item.description ?? ''}`);
      for (const tag of tags) {
        counts.set(tag, (counts.get(tag) ?? 0) + 1);
      }
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12)
      .map(([tag]) => tag);
  }, [videos]);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const topic = params.get('topic');
    const hashtag = params.get('hashtag');
    const creator = params.get('creator');
    const content = params.get('content');

    setTopicFilter(topic && topic.trim() ? topic.trim().toLowerCase() : 'all');
    setHashtagFilter(hashtag && hashtag.trim() ? hashtag.trim().toLowerCase() : 'all');
    setCreatorFilter(creator && creator.trim() ? creator.trim() : 'all');
    setContentFilter(content === 'protected' ? 'protected' : 'all');
  }, [location.search]);

  const visibleVideos = videos.filter((item) => {
    if (audience === 'following' && !followingCreatorIds.has(item.creatorId)) return false;
    if (contentFilter === 'protected' && !item.originBundleId) return false;
    if (creatorFilter !== 'all' && item.creatorId !== creatorFilter) return false;
    if (topicFilter !== 'all' && inferTopic(item) !== topicFilter) return false;
    if (hashtagFilter !== 'all') {
      const tags = extractHashtags(`${item.title} ${item.description ?? ''}`);
      if (!tags.includes(hashtagFilter)) return false;
    }
    return true;
  });

  const promotedVideo = useMemo(() => {
    if (visibleVideos.length === 0) return null;
    return [...visibleVideos].sort((a, b) => {
      const scoreA = a.viewCount * 1.4 + a.likeCount * 3 + a.commentCount * 4;
      const scoreB = b.viewCount * 1.4 + b.likeCount * 3 + b.commentCount * 4;
      return scoreB - scoreA;
    })[0] ?? null;
  }, [visibleVideos]);

  const categoryRows = useMemo(() => {
    if (visibleVideos.length === 0) return [] as Array<{ key: string; label: string; items: VideoMeta[] }>;

    const grouped = new Map<string, VideoMeta[]>();
    for (const item of visibleVideos) {
      if (promotedVideo && item.id === promotedVideo.id) continue;
      const topic = inferTopic(item);
      if (!grouped.has(topic)) grouped.set(topic, []);
      grouped.get(topic)!.push(item);
    }

    const rows = [...grouped.entries()]
      .sort((a, b) => b[1].length - a[1].length)
      .slice(0, 7)
      .map(([topic, items]) => ({
        key: topic,
        label: topic.charAt(0).toUpperCase() + topic.slice(1),
        items: items.slice(0, 10),
      }));

    const forYou = visibleVideos.filter((item) => !promotedVideo || item.id !== promotedVideo.id).slice(0, 10);
    return [{ key: 'for-you', label: 'For You', items: forYou }, ...rows.filter((row) => row.items.length > 0)];
  }, [visibleVideos, promotedVideo]);

  function recommendationHref(href?: string): string {
    if (!href || !href.trim()) return '/abigail';
    return href;
  }

  function recommendationIsExternal(href?: string): boolean {
    return Boolean(href && /^https?:\/\//i.test(href));
  }

  const categoriesBar = (
    <div
      style={{
        border: '1px solid rgba(255,255,255,0.12)',
        borderRadius: 999,
        padding: '6px 8px',
        background: 'rgba(15,23,42,0.6)',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        overflowX: 'auto',
        whiteSpace: 'nowrap',
      }}
    >
      <span style={{ fontSize: 12, color: '#cbd5e1' }}>Categories</span>

      <select
        value={creatorFilter}
        onChange={(e) => setCreatorFilter(e.target.value)}
        style={{
          minWidth: 150,
          padding: '5px 8px',
          borderRadius: 999,
          background: '#0b1220',
          color: '#fff',
          border: '1px solid #374151',
          fontSize: 12,
        }}
      >
        <option value="all">All creators</option>
        {creatorOptions.map((creator) => (
          <option key={creator.id} value={creator.id}>{creator.name}</option>
        ))}
      </select>

      <select
        value={topicFilter}
        onChange={(e) => setTopicFilter(e.target.value)}
        style={{
          minWidth: 130,
          padding: '5px 8px',
          borderRadius: 999,
          background: '#0b1220',
          color: '#fff',
          border: '1px solid #374151',
          fontSize: 12,
        }}
      >
        <option value="all">All topics</option>
        {topicOptions.map((topic) => (
          <option key={topic} value={topic}>{topic}</option>
        ))}
      </select>

      <button
        type="button"
        onClick={() => setHashtagFilter('all')}
        style={{ border: '1px solid #374151', borderRadius: 999, background: hashtagFilter === 'all' ? '#111827' : 'transparent', color: '#fff', padding: '4px 8px', fontSize: 12, cursor: 'pointer' }}
      >
        #all
      </button>
      {topHashtags.map((tag) => (
        <button
          key={tag}
          type="button"
          onClick={() => setHashtagFilter(tag)}
          style={{ border: '1px solid #374151', borderRadius: 999, background: hashtagFilter === tag ? '#111827' : 'transparent', color: '#fff', padding: '4px 8px', fontSize: 12, cursor: 'pointer' }}
        >
          {tag}
        </button>
      ))}
    </div>
  );

  return (
    <main style={{ maxWidth: mode === 'reels' ? 1080 : 1160, margin: '0 auto', color: '#fff', paddingInline: 8 }}>
      <div
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 20,
          backdropFilter: 'blur(8px)',
          background: 'linear-gradient(180deg, rgba(0,0,0,0.75), rgba(0,0,0,0.2))',
          paddingTop: 8,
          marginBottom: 8,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
          <h2 style={{ margin: '0 0 0 4px', fontSize: 22 }}>Origin</h2>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <Link
              to="/upload"
              style={{
                border: '1px solid #374151',
                borderRadius: 999,
                padding: '5px 12px',
                background: '#111827',
                color: '#fff',
                fontWeight: 700,
                textDecoration: 'none',
                fontSize: 13,
              }}
            >
              Create post
            </Link>
            <div
              style={{
                display: 'flex',
                gap: 8,
                background: 'rgba(255,255,255,0.12)',
                borderRadius: 999,
                padding: 4,
                width: 'fit-content',
              }}
            >
              <button
                onClick={() => setMode('reels')}
                style={{
                  border: 'none',
                  cursor: 'pointer',
                  borderRadius: 999,
                  padding: '5px 12px',
                  background: mode === 'reels' ? '#fff' : 'transparent',
                  color: mode === 'reels' ? '#111827' : '#e5e7eb',
                  fontWeight: 700,
                }}
              >
                Reels
              </button>
              <button
                onClick={() => setMode('cards')}
                style={{
                  border: 'none',
                  cursor: 'pointer',
                  borderRadius: 999,
                  padding: '5px 12px',
                  background: mode === 'cards' ? '#fff' : 'transparent',
                  color: mode === 'cards' ? '#111827' : '#e5e7eb',
                  fontWeight: 700,
                }}
              >
                Cards
              </button>
            </div>
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 8,
            marginBottom: 8,
            background: 'rgba(255,255,255,0.08)',
            borderRadius: 999,
            padding: 4,
            width: '100%',
          }}
        >
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => setAudience('all')}
              style={{
                border: 'none',
                cursor: 'pointer',
                borderRadius: 999,
                padding: '5px 12px',
                background: audience === 'all' ? '#111827' : 'transparent',
                color: '#fff',
                fontWeight: 600,
              }}
            >
              All
            </button>
            <button
              onClick={() => setAudience('following')}
              style={{
                border: 'none',
                cursor: 'pointer',
                borderRadius: 999,
                padding: '5px 12px',
                background: audience === 'following' ? '#111827' : 'transparent',
                color: '#fff',
                fontWeight: 600,
              }}
            >
              Following
            </button>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label style={{ display: 'flex', gap: 4, alignItems: 'center', fontSize: 12, color: '#e5e7eb' }}>
              <input
                type="checkbox"
                checked={contentFilter === 'protected'}
                onChange={(e) => setContentFilter(e.target.checked ? 'protected' : 'all')}
              />
              Protected
            </label>
            <button
              type="button"
              onClick={() => setShowFilters((prev) => !prev)}
              style={{
                border: '1px solid #374151',
                borderRadius: 999,
                padding: '5px 10px',
                background: showFilters ? '#111827' : 'transparent',
                color: '#fff',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {showFilters ? 'Hide filters' : 'Show filters'}
            </button>
          </div>
        </div>

        {showFilters ? <div style={{ marginBottom: 8 }}>{categoriesBar}</div> : null}
      </div>

      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10, marginBottom: 10 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 15 }}>🧠 Abigail</h3>
            <p style={{ margin: '3px 0 0', color: '#9ca3af', fontSize: 12 }}>
              Personalized suggestions in your feed context.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: notificationStateColor, fontSize: 12 }}>{notificationStateLabel}</span>
            {abigailOffline ? <span style={{ color: '#fbbf24', fontSize: 12 }}>fallback mode</span> : null}
            {supportsBrowserNotifications() && notificationPermission !== 'granted' ? (
              <button
                type="button"
                onClick={() => void enableAbigailAlerts()}
                style={{ border: '1px solid #374151', borderRadius: 999, background: '#111827', color: '#fff', padding: '5px 10px', cursor: 'pointer', fontSize: 12 }}
              >
                Enable alerts
              </button>
            ) : null}
            {supportsBrowserNotifications() && notificationPermission === 'granted' ? (
              <button
                type="button"
                onClick={() => sendTestAbigailNotification()}
                style={{ border: '1px solid #374151', borderRadius: 999, background: '#111827', color: '#fff', padding: '5px 10px', cursor: 'pointer', fontSize: 12 }}
              >
                Test notification
              </button>
            ) : null}
            <button
              type="button"
              onClick={() => void refreshAbigailRecommendations()}
              disabled={abigailLoading}
              style={{ border: '1px solid #374151', borderRadius: 999, background: '#111827', color: '#fff', padding: '5px 10px', cursor: 'pointer', fontSize: 12 }}
            >
              {abigailLoading ? 'Refreshing…' : 'Refresh'}
            </button>
            <Link to="/abigail" style={{ border: '1px solid #374151', borderRadius: 999, background: '#111827', color: '#fff', padding: '5px 10px', textDecoration: 'none', fontSize: 12 }}>
              Open Abigail
            </Link>
          </div>
        </div>

        <div style={{ display: 'grid', gap: 6, marginTop: 8 }}>
          {abigailItems.length === 0 ? (
            <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>
              No recommendations yet. Open Abigail to personalize.
            </p>
          ) : (
            abigailItems.map((item) => {
              const href = recommendationHref(item.href);
              const external = recommendationIsExternal(item.href);
              const commonStyle = {
                border: '1px solid #1f2937',
                borderRadius: 8,
                padding: '6px 8px',
                background: '#0f172a',
                textDecoration: 'none',
                display: 'block',
              } as const;

              if (external) {
                return (
                  <a key={item.id} href={href} target="_blank" rel="noreferrer" style={commonStyle}>
                    <p style={{ margin: 0, color: '#e5e7eb', fontSize: 13 }}>
                      <strong>{item.title}</strong> <span style={{ color: '#9ca3af' }}>({item.kind})</span>
                    </p>
                    <p style={{ margin: '2px 0 0', color: '#93c5fd', fontSize: 12 }}>{item.reason}</p>
                  </a>
                );
              }

              return (
                <Link key={item.id} to={href} style={commonStyle}>
                  <p style={{ margin: 0, color: '#e5e7eb', fontSize: 13 }}>
                    <strong>{item.title}</strong> <span style={{ color: '#9ca3af' }}>({item.kind})</span>
                  </p>
                  <p style={{ margin: '2px 0 0', color: '#93c5fd', fontSize: 12 }}>{item.reason}</p>
                </Link>
              );
            })
          )}
        </div>
      </section>

      {mode === 'reels' ? (
        <section style={{ display: 'grid', gap: 10 }}>
          <div style={{ width: '100%', maxWidth: 1040, margin: '0 auto' }}>
            <ReelsDesktop
              videos={visibleVideos}
              onRequestMore={() => {
                if (!loading && hasMore) {
                  void loadMore();
                }
              }}
            />
          </div>
        </section>
      ) : (
        <section style={{ display: 'grid', gap: 14 }}>
          {promotedVideo ? (
            <Link
              to={`/video/${promotedVideo.id}`}
              style={{
                textDecoration: 'none',
                color: '#fff',
                borderRadius: 14,
                overflow: 'hidden',
                border: '1px solid rgba(255,255,255,0.16)',
                background: 'linear-gradient(135deg, rgba(14,116,144,0.24), rgba(30,64,175,0.24))',
                display: 'grid',
                gridTemplateColumns: 'minmax(0, 360px) minmax(0, 1fr)',
              }}
            >
              <div style={{ minHeight: 210, background: '#020617' }}>
                <img
                  src={resolveApiAssetUrl(promotedVideo.thumbnailUrl) || resolveApiAssetUrl(promotedVideo.videoUrl)}
                  alt={promotedVideo.title}
                  style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }}
                />
              </div>
              <div style={{ padding: '14px 16px' }}>
                <div style={{ fontSize: 11, color: '#67e8f9', marginBottom: 6 }}>Promoted</div>
                <h3 style={{ margin: 0, fontSize: 24 }}>{promotedVideo.title}</h3>
                <p style={{ margin: '6px 0 0', color: '#bfdbfe', fontSize: 13 }}>
                  by {promotedVideo.creatorDisplayName || promotedVideo.creatorUsername || 'Unknown creator'}
                </p>
                {promotedVideo.description ? (
                  <p style={{ margin: '10px 0 0', color: '#d1d5db', fontSize: 14, lineHeight: 1.45 }}>
                    {promotedVideo.description.slice(0, 200)}
                    {promotedVideo.description.length > 200 ? '…' : ''}
                  </p>
                ) : null}
                <p style={{ margin: '10px 0 0', color: '#9ca3af', fontSize: 12 }}>
                  👁 {promotedVideo.viewCount} · ❤️ {promotedVideo.likeCount} · 💬 {promotedVideo.commentCount}
                </p>
              </div>
            </Link>
          ) : null}

          {categoryRows.map((row, rowIndex) => (
            <section key={row.key}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <h3 style={{ margin: 0, fontSize: 17 }}>{row.label}</h3>
                <span style={{ color: '#9ca3af', fontSize: 12 }}>{row.items.length} videos</span>
              </div>
              <div
                onScroll={(event) => {
                  const el = event.currentTarget;
                  if (rowIndex === categoryRows.length - 1 && el.scrollWidth - el.scrollLeft - el.clientWidth < 320) {
                    void loadMore();
                  }
                }}
                style={{
                  display: 'grid',
                  gridAutoFlow: 'column',
                  gridAutoColumns: 'minmax(250px, 250px)',
                  gap: 10,
                  overflowX: 'auto',
                  overflowY: 'hidden',
                  paddingBottom: 2,
                }}
              >
                {row.items.map((v, idx) => (
                  <VideoCard key={`${row.key}-${v.id}`} video={v} variant="grid" priority={rowIndex === 0 && idx < 2} />
                ))}
              </div>
            </section>
          ))}
        </section>
      )}

      {loading && <p style={{ color: '#cbd5e1', padding: '8px 2px' }}>Loading…</p>}
      {!loading && hasMore && mode === 'cards' && (
        <button onClick={() => void loadMore()} style={{ padding: '8px 12px', borderRadius: 10, border: '1px solid #374151', background: '#111827', color: '#fff' }}>
          Load more
        </button>
      )}
      {!hasMore && visibleVideos.length > 0 && <p style={{ color: '#9ca3af' }}>You’re all caught up.</p>}
      {!loading && visibleVideos.length === 0 && (
        <p style={{ color: '#9ca3af' }}>
          {audience === 'following'
            ? 'No videos from followed creators yet.'
            : contentFilter === 'protected'
            ? 'No protected uploads yet. Create one from Create post.'
            : 'No videos yet — be the first to upload.'}
        </p>
      )}
    </main>
  );
}
