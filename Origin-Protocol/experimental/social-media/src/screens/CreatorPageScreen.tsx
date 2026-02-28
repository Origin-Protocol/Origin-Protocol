import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { liveApi, messagingApi, usersApi } from '../api/client';
import { LiveSession, User, VideoMeta } from '../types';
import VideoCard from '../components/VideoCard';
import { useAuth } from '../hooks/useAuth';

type CatalogFilter = 'all' | 'protected' | 'verified';
type CreatorTab = 'overview' | 'protected-catalog' | 'verification-activity';

const PAGE_SIZE = 4;
const SUBSCRIPTIONS_KEY = 'origin_creator_subscriptions_v1';

function loadSubscriptions(): Record<string, boolean> {
  try {
    const raw = window.localStorage.getItem(SUBSCRIPTIONS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, boolean>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function saveSubscription(creatorId: string, subscribed: boolean) {
  const existing = loadSubscriptions();
  existing[creatorId] = subscribed;
  window.localStorage.setItem(SUBSCRIPTIONS_KEY, JSON.stringify(existing));
}

export default function CreatorPageScreen() {
  const { user } = useAuth();
  const { id: routeId = '', username: routeUsername = '' } = useParams();
  const [profile, setProfile] = useState<User | null>(null);
  const [videos, setVideos] = useState<VideoMeta[]>([]);
  const [tab, setTab] = useState<CreatorTab>('overview');
  const [filter, setFilter] = useState<CatalogFilter>('all');
  const [page, setPage] = useState(1);
  const [subscribed, setSubscribed] = useState(false);
  const [ctaMsg, setCtaMsg] = useState<string | null>(null);
  const [creatorNotifMuted, setCreatorNotifMuted] = useState(false);
  const [creatorBroadcastNotifyOn, setCreatorBroadcastNotifyOn] = useState(true);
  const [profileStats, setProfileStats] = useState<{
    followersCount: number;
    followingCount: number;
    totalVideos: number;
    totalViews: number;
    totalLikes: number;
    totalVerified: number;
    totalProtected: number;
  } | null>(null);
  const [activeSocialList, setActiveSocialList] = useState<'followers' | 'following'>('followers');
  const [socialList, setSocialList] = useState<User[]>([]);
  const [socialTotal, setSocialTotal] = useState(0);
  const [liveSession, setLiveSession] = useState<LiveSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const creatorId = profile?.id ?? routeId;
  const bannerUrl = useMemo(() => {
    if (!profile) return null;
    const candidate = [profile.bannerPhoto]
      .find((value) => typeof value === 'string' && value.trim().length > 0);
    return candidate ?? null;
  }, [profile]);

  const isOwnCreatorPage = Boolean(user?.id && creatorId && user.id === creatorId);

  async function refreshSocialGraph(targetType: 'followers' | 'following') {
    if (!creatorId) return;
    const graph = await usersApi.getSocialGraph(creatorId, targetType, 18);
    setSocialList(graph.items);
    setSocialTotal(graph.total);
  }

  useEffect(() => {
    if (!routeId && !routeUsername) {
      setLoading(false);
      setError('Missing creator profile route.');
      return;
    }

    let mounted = true;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const resolvedCreator = routeId
          ? await usersApi.getProfile(routeId)
          : await usersApi.getByUsername(routeUsername);
        const resolvedId = resolvedCreator.user.id;

        const [profileData, videosData, statsData, liveData] = await Promise.all([
          Promise.resolve(resolvedCreator),
          usersApi.getVideos(resolvedId),
          usersApi.getProfileStats(resolvedId),
          liveApi.listSessions('live', 120),
        ]);
        if (!mounted) return;
        setProfile(profileData.user);
        setVideos(videosData.items);
        setProfileStats(statsData.stats);
        setLiveSession(liveData.items.find((item) => item.hostUserId === resolvedId && item.status === 'live') ?? null);
      } catch (err) {
        if (!mounted) return;
        setError((err as Error).message || 'Unable to load creator page.');
      } finally {
        if (mounted) setLoading(false);
      }
    }

    void load();
    return () => {
      mounted = false;
    };
  }, [routeId, routeUsername]);

  useEffect(() => {
    if (!creatorId) return;
    let cancelled = false;

    async function refreshLivePresence() {
      try {
        const liveData = await liveApi.listSessions('live', 120);
        if (cancelled) return;
        setLiveSession(liveData.items.find((item) => item.hostUserId === creatorId && item.status === 'live') ?? null);
      } catch {
        if (cancelled) return;
        setLiveSession(null);
      }
    }

    const timer = window.setInterval(() => {
      void refreshLivePresence();
    }, 15_000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [creatorId]);

  const featuredVideo = useMemo(() => {
    if (videos.length === 0) return null;
    const protectedFirst = videos.find((video) => Boolean(video.originBundleId));
    return protectedFirst ?? videos[0];
  }, [videos]);

  const featuredVideoId = featuredVideo?.id;

  const visibleVideos = useMemo(() => {
    const base = filter === 'protected'
      ? videos.filter((video) => Boolean(video.originBundleId))
      : filter === 'verified'
        ? videos.filter((video) => Boolean(video.originVerified))
        : videos;

    return base.filter((video) => video.id !== featuredVideoId);
  }, [videos, filter, featuredVideoId]);

  const pagedVideos = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return visibleVideos.slice(start, start + PAGE_SIZE);
  }, [visibleVideos, page]);

  const totalPages = Math.max(1, Math.ceil(visibleVideos.length / PAGE_SIZE));

  const verificationActivity = useMemo(() => {
    return videos
      .filter((video) => video.originVerificationCheckedAt || (video.originReasons?.length ?? 0) > 0)
      .sort((a, b) => {
        const aTs = a.originVerificationCheckedAt ?? a.createdAt;
        const bTs = b.originVerificationCheckedAt ?? b.createdAt;
        return bTs.localeCompare(aTs);
      });
  }, [videos]);

  useEffect(() => {
    setPage(1);
  }, [filter, tab]);

  useEffect(() => {
    if (tab === 'protected-catalog' && filter !== 'protected') {
      setFilter('protected');
      return;
    }
    if (tab === 'overview' && filter === 'protected') {
      setFilter('all');
    }
  }, [tab, filter]);

  const stats = useMemo(() => {
    const computed = {
      total: videos.length,
      protectedCount: videos.filter((video) => Boolean(video.originBundleId)).length,
      verifiedCount: videos.filter((video) => Boolean(video.originVerified)).length,
      totalViews: videos.reduce((sum, video) => sum + (video.viewCount || 0), 0),
      totalLikes: videos.reduce((sum, video) => sum + (video.likeCount || 0), 0),
    };

    if (!profileStats) {
      return computed;
    }

    return {
      total: profileStats.totalVideos,
      protectedCount: profileStats.totalProtected,
      verifiedCount: profileStats.totalVerified,
      totalViews: profileStats.totalViews,
      totalLikes: profileStats.totalLikes,
    };
  }, [videos, profileStats]);

  const followersCount = profileStats?.followersCount ?? (subscribed ? 1 : 0);
  const followingCount = profileStats?.followingCount ?? 0;
  const trustScore = stats.total > 0
    ? Math.round(((stats.verifiedCount * 0.7 + stats.protectedCount * 0.3) / Math.max(1, stats.total)) * 100)
    : 0;
  const recentActivity = useMemo(() => {
    return [...videos]
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, 5)
      .map((video) => ({
        id: video.id,
        title: video.title,
        createdAt: video.createdAt,
        verified: Boolean(video.originVerified),
        protected: Boolean(video.originBundleId),
      }));
  }, [videos]);

  useEffect(() => {
    if (!creatorId) return;
    const map = loadSubscriptions();
    setSubscribed(Boolean(map[creatorId]));
  }, [creatorId]);

  useEffect(() => {
    if (!creatorId || !user) return;
    let cancelled = false;

    async function loadCreatorNotificationPref() {
      try {
        const res = await messagingApi.getCreatorNotificationPreference(creatorId);
        if (cancelled) return;
        setCreatorNotifMuted(Boolean(res.preference.muted));
        setCreatorBroadcastNotifyOn(res.preference.broadcast !== 'off');
        setSubscribed(res.preference.upload !== 'off' && !res.preference.muted);
      } catch {
        if (cancelled) return;
        setCreatorNotifMuted(false);
        setCreatorBroadcastNotifyOn(true);
      }
    }

    void loadCreatorNotificationPref();
    return () => {
      cancelled = true;
    };
  }, [creatorId, user]);

  useEffect(() => {
    if (!creatorId) return;
    let cancelled = false;

    async function loadSocialGraph() {
      try {
        const graph = await usersApi.getSocialGraph(creatorId, activeSocialList, 18);
        if (cancelled) return;
        setSocialList(graph.items);
        setSocialTotal(graph.total);
      } catch {
        if (cancelled) return;
        setSocialList([]);
        setSocialTotal(0);
      }
    }

    void loadSocialGraph();
    return () => {
      cancelled = true;
    };
  }, [creatorId, activeSocialList]);

  async function toggleSubscribe() {
    if (!creatorId) return;
    const next = !subscribed;
    setSubscribed(next);
    saveSubscription(creatorId, next);
    try {
      const pref = await messagingApi.updateCreatorNotificationPreference(creatorId, {
        upload: next ? 'in_app' : 'off',
        broadcast: next ? (creatorBroadcastNotifyOn ? 'in_app' : 'off') : 'off',
        muted: false,
      });
      setCreatorNotifMuted(Boolean(pref.preference.muted));
      setCreatorBroadcastNotifyOn(pref.preference.broadcast !== 'off');

      const refreshed = await usersApi.getProfileStats(creatorId);
      setProfileStats(refreshed.stats);
      await refreshSocialGraph('followers');
      if (activeSocialList === 'following') {
        await refreshSocialGraph('following');
      }
      setCtaMsg(next ? 'Subscribed. You will see more updates from this creator.' : 'Subscription removed.');
    } catch (err) {
      setSubscribed(!next);
      saveSubscription(creatorId, !next);
      setCtaMsg((err as Error).message || 'Unable to update subscription right now.');
    }
  }

  async function toggleCreatorMute() {
    if (!creatorId) return;
    try {
      const next = !creatorNotifMuted;
      await messagingApi.updateCreatorNotificationPreference(creatorId, { muted: next });
      setCreatorNotifMuted(next);
      await refreshSocialGraph(activeSocialList);
      setCtaMsg(next ? 'Creator notifications muted.' : 'Creator notifications unmuted.');
    } catch (err) {
      setCtaMsg((err as Error).message || 'Unable to update creator notification preference.');
    }
  }

  async function toggleBroadcastNotify() {
    if (!creatorId) return;
    try {
      const next = !creatorBroadcastNotifyOn;
      await messagingApi.updateCreatorNotificationPreference(creatorId, {
        broadcast: next ? 'in_app' : 'off',
      });
      setCreatorBroadcastNotifyOn(next);
      await refreshSocialGraph(activeSocialList);
      setCtaMsg(next ? 'Broadcast post notifications enabled.' : 'Broadcast post notifications disabled.');
    } catch (err) {
      setCtaMsg((err as Error).message || 'Unable to update creator broadcast notifications.');
    }
  }

  function handleVideoDeleted(videoId: string) {
    setVideos((prev) => prev.filter((video) => video.id !== videoId));
  }

  if (loading) return <main style={{ maxWidth: 900, margin: '24px auto', color: '#e5e7eb', padding: 12 }}>Loading creator page…</main>;
  if (error) {
    return (
      <main style={{ maxWidth: 900, margin: '24px auto', color: '#e5e7eb', padding: 12 }}>
        <h2 style={{ marginBottom: 8 }}>Creator page unavailable</h2>
        <p style={{ color: '#fca5a5' }}>{error}</p>
        <Link to="/" style={{ color: '#93c5fd' }}>Back to feed</Link>
      </main>
    );
  }
  if (!profile) return <main style={{ maxWidth: 900, margin: '24px auto', color: '#e5e7eb', padding: 12 }}>Creator not found.</main>;

  return (
    <main style={{ maxWidth: 900, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>
      {bannerUrl ? (
        <section
          style={{
            border: '1px solid #1f2937',
            borderRadius: 14,
            background: '#0b1220',
            overflow: 'hidden',
            marginBottom: 12,
          }}
        >
          <img
            src={bannerUrl}
            alt={`${profile.displayName} banner`}
            style={{
              width: '100%',
              height: 150,
              objectFit: 'cover',
              objectPosition: 'center',
              display: 'block',
            }}
          />
        </section>
      ) : null}

      <section style={{ border: '1px solid #1f2937', borderRadius: 14, padding: 12, background: 'linear-gradient(180deg,#0b1220,#0f172a)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {liveSession ? (
            <Link
              to={`/live/${liveSession.id}`}
              aria-label="Open creator live room"
              title="Open live room"
              style={{
                width: 72,
                height: 72,
                borderRadius: '50%',
                overflow: 'hidden',
                background: '#1f2937',
                position: 'relative',
                display: 'block',
                border: '2px solid #22c55e',
              }}
            >
              {profile.avatarUrl
                ? <img src={profile.avatarUrl} alt="avatar" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                : <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', fontSize: 30, color: '#111827', background: '#d1d5db' }}>👤</span>}
              <span
                style={{
                  position: 'absolute',
                  right: 4,
                  bottom: 4,
                  width: 13,
                  height: 13,
                  borderRadius: '50%',
                  background: '#22c55e',
                  border: '2px solid #0b1220',
                }}
              />
            </Link>
          ) : (
            <div style={{ width: 72, height: 72, borderRadius: '50%', overflow: 'hidden', background: '#1f2937' }}>
              {profile.avatarUrl
                ? <img src={profile.avatarUrl} alt="avatar" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                : <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', fontSize: 30 }}>👤</span>}
            </div>
          )}
          <div style={{ flex: 1, minWidth: 0 }}>
            <h2 style={{ margin: 0 }}>{profile.displayName}</h2>
            <p style={{ margin: 0, color: '#9ca3af' }}>@{profile.username}</p>
            {profile.creatorKeyId ? <p style={{ margin: 0, color: '#86efac', fontSize: 12 }}>✅ Origin verified creator</p> : null}
            {liveSession ? (
              <div style={{ marginTop: 6, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span
                  style={{
                    border: '1px solid #22c55e',
                    borderRadius: 999,
                    color: '#bbf7d0',
                    fontSize: 11,
                    fontWeight: 700,
                    letterSpacing: 0.3,
                    padding: '2px 8px',
                    background: 'rgba(20,83,45,0.35)',
                  }}
                >
                  🟢 LIVE NOW
                </span>
                <Link
                  to={`/live/${liveSession.id}`}
                  style={{ color: '#93c5fd', fontSize: 12, textDecoration: 'none' }}
                >
                  Join live room
                </Link>
              </div>
            ) : null}
          </div>
        </div>
        {profile.bio ? <p style={{ marginBottom: 0, marginTop: 10, color: '#d1d5db' }}>{profile.bio}</p> : null}
      </section>

      <section style={{ marginTop: 12, border: '1px solid #1f2937', borderRadius: 12, padding: 12, background: '#0b1220' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))', alignItems: 'start', gap: 10 }}>
          <div style={{ minWidth: 0 }}>
            <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>Community</p>
            <p style={{ margin: '2px 0 0', fontWeight: 700 }}>
              {followersCount.toLocaleString()} followers • {followingCount.toLocaleString()} following
            </p>
            <p style={{ margin: '6px 0 0', color: '#9ca3af', fontSize: 12 }}>
              Choose which updates you want from this creator.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-start' }}>
            <button
              type="button"
              onClick={() => void toggleSubscribe()}
              style={{ border: '1px solid #374151', borderRadius: 999, background: subscribed ? '#065f46' : '#111827', color: '#fff', padding: '6px 12px', cursor: 'pointer' }}
            >
              {subscribed ? '✓ Subscribed' : 'Subscribe'}
            </button>
            <button
              type="button"
              onClick={() => void toggleBroadcastNotify()}
              style={{ border: '1px solid #374151', borderRadius: 999, background: creatorBroadcastNotifyOn ? '#0f766e' : '#111827', color: '#fff', padding: '6px 12px', cursor: 'pointer' }}
            >
              {creatorBroadcastNotifyOn ? '🔔 Broadcast alerts on' : '🔕 Broadcast alerts off'}
            </button>
            <button
              type="button"
              onClick={() => void toggleCreatorMute()}
              style={{ border: '1px solid #374151', borderRadius: 999, background: creatorNotifMuted ? '#7f1d1d' : '#111827', color: '#fff', padding: '6px 12px', cursor: 'pointer' }}
            >
              {creatorNotifMuted ? 'Unmute creator alerts' : 'Mute creator alerts'}
            </button>
            <Link
              to="/upload"
              style={{ border: '1px solid #374151', borderRadius: 999, color: '#fff', padding: '6px 12px', textDecoration: 'none', background: '#111827' }}
            >
              Collaborate
            </Link>
          </div>
        </div>
        {ctaMsg ? <p style={{ margin: '8px 0 0', color: '#93c5fd', fontSize: 12 }}>{ctaMsg}</p> : null}
      </section>

      {featuredVideo ? (
        <section style={{ marginTop: 12, border: '1px solid #1f2937', borderRadius: 12, padding: 10, background: '#0b1220' }}>
          <h3 style={{ marginTop: 0 }}>Featured / Pinned</h3>
          <p style={{ marginTop: 0, color: '#9ca3af', fontSize: 12 }}>
            Highlighted by protected-priority selection.
          </p>
          <VideoCard
            video={featuredVideo}
            allowDelete={isOwnCreatorPage}
            onDeleted={handleVideoDeleted}
          />
        </section>
      ) : null}

      <section style={{ marginTop: 12, display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(145px,1fr))', gap: 8 }}>
        <StatCard label="Videos" value={stats.total} />
        <StatCard label="Protected" value={stats.protectedCount} />
        <StatCard label="Verified" value={stats.verifiedCount} />
        <StatCard label="Views" value={stats.totalViews} />
        <StatCard label="Likes" value={stats.totalLikes} />
      </section>

      <section style={{ marginTop: 12, display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))' }}>
        <div style={{ border: '1px solid #1f2937', borderRadius: 12, padding: 10, background: '#0b1220' }}>
          <strong style={{ display: 'block', marginBottom: 8 }}>Social graph</strong>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <button
              type="button"
              onClick={() => setActiveSocialList('followers')}
              style={{
                border: '1px solid #374151',
                borderRadius: 999,
                padding: '4px 10px',
                background: activeSocialList === 'followers' ? '#111827' : 'transparent',
                color: '#fff',
                cursor: 'pointer',
              }}
            >
              Followers ({followersCount.toLocaleString()})
            </button>
            <button
              type="button"
              onClick={() => setActiveSocialList('following')}
              style={{
                border: '1px solid #374151',
                borderRadius: 999,
                padding: '4px 10px',
                background: activeSocialList === 'following' ? '#111827' : 'transparent',
                color: '#fff',
                cursor: 'pointer',
              }}
            >
              Following ({followingCount.toLocaleString()})
            </button>
          </div>
          {socialList.length === 0 ? (
            <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>No users to show yet.</p>
          ) : (
            <div style={{ display: 'grid', gap: 6 }}>
              {socialList.map((person) => (
                <Link
                  key={person.id}
                  to={`/creator/${person.id}`}
                  style={{
                    border: '1px solid #1f2937',
                    borderRadius: 8,
                    padding: '6px 8px',
                    textDecoration: 'none',
                    color: '#e5e7eb',
                    background: '#0f172a',
                  }}
                >
                  <strong>{person.displayName}</strong>
                  <span style={{ display: 'block', color: '#9ca3af', fontSize: 12 }}>@{person.username}</span>
                </Link>
              ))}
              {socialTotal > socialList.length ? (
                <p style={{ margin: 0, color: '#9ca3af', fontSize: 11 }}>
                  Showing {socialList.length} of {socialTotal}
                </p>
              ) : null}
            </div>
          )}
        </div>

        <div style={{ border: '1px solid #1f2937', borderRadius: 12, padding: 10, background: '#0b1220' }}>
          <strong style={{ display: 'block', marginBottom: 8 }}>Trust & activity</strong>
          <p style={{ margin: 0, color: '#93c5fd', fontSize: 13 }}>
            Trust score: <strong>{trustScore}%</strong>
          </p>
          <p style={{ margin: '4px 0 8px', color: '#9ca3af', fontSize: 12 }}>
            Based on verified and protected upload ratio.
          </p>
          <div style={{ display: 'grid', gap: 6 }}>
            {recentActivity.length === 0 ? (
              <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>No recent activity.</p>
            ) : recentActivity.map((item) => (
              <div key={item.id} style={{ border: '1px solid #1f2937', borderRadius: 8, padding: '6px 8px', background: '#0f172a' }}>
                <p style={{ margin: 0, color: '#e5e7eb', fontSize: 12 }}>
                  {item.verified ? '✅' : item.protected ? '🛡' : '📹'} {item.title}
                </p>
                <p style={{ margin: '2px 0 0', color: '#9ca3af', fontSize: 11 }}>
                  {new Date(item.createdAt).toLocaleString()}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section style={{ marginTop: 12, border: '1px solid #1f2937', borderRadius: 12, padding: 12, background: '#0b1220' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))', gap: 12 }}>
          <div>
            <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>Sections</p>
            <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
              <FilterButton active={tab === 'overview'} onClick={() => setTab('overview')} label="Overview" />
              <FilterButton active={tab === 'protected-catalog'} onClick={() => setTab('protected-catalog')} label="Protected Catalog" />
              <FilterButton active={tab === 'verification-activity'} onClick={() => setTab('verification-activity')} label="Verification Activity" />
            </div>
          </div>
          {tab !== 'verification-activity' ? (
            <div>
              <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>Catalog filters</p>
              <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
                <FilterButton active={filter === 'all'} onClick={() => setFilter('all')} label="All" />
                <FilterButton active={filter === 'protected'} onClick={() => setFilter('protected')} label="🛡 Protected" />
                <FilterButton active={filter === 'verified'} onClick={() => setFilter('verified')} label="✅ Verified" />
              </div>
            </div>
          ) : (
            <div>
              <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>Verification timeline</p>
              <p style={{ margin: '8px 0 0', color: '#cbd5e1', fontSize: 12 }}>
                Browse latest verification checks and reason flags for this creator.
              </p>
            </div>
          )}
        </div>
      </section>

      {tab === 'verification-activity' ? (
        <section style={{ marginTop: 12, border: '1px solid #1f2937', borderRadius: 12, padding: 10, background: '#0b1220' }}>
          <h3 style={{ marginTop: 0 }}>Verification Activity</h3>
          {verificationActivity.length === 0 ? (
            <p style={{ color: '#9ca3af', marginBottom: 0 }}>No verification activity yet.</p>
          ) : (
            <div style={{ display: 'grid', gap: 8 }}>
              {verificationActivity.map((video) => (
                <div key={video.id} style={{ border: '1px solid #1f2937', borderRadius: 10, padding: 8, background: '#0f172a' }}>
                  <p style={{ margin: 0, color: '#e5e7eb' }}>
                    <strong>{video.originVerified ? '✅' : '⚠️'}</strong> {video.title}
                  </p>
                  <p style={{ margin: '4px 0 0', color: '#9ca3af', fontSize: 12 }}>
                    Checked: {video.originVerificationCheckedAt ? new Date(video.originVerificationCheckedAt).toLocaleString() : 'Not recorded'}
                  </p>
                  {video.originReasons?.length ? (
                    <p style={{ margin: '4px 0 0', color: '#fcd34d', fontSize: 12 }}>
                      Reasons: {video.originReasons.length}
                    </p>
                  ) : null}
                  <Link to={`/verify/${video.id}`} style={{ color: '#93c5fd', fontSize: 12 }}>
                    Open verification report
                  </Link>
                </div>
              ))}
            </div>
          )}
        </section>
      ) : (
        <section style={{ marginTop: 12, border: '1px solid #1f2937', borderRadius: 12, padding: 10, background: '#0b1220' }}>
          <h3 style={{ margin: '0 0 8px' }}>{tab === 'protected-catalog' ? 'Protected Catalog' : 'Creator Catalog'}</h3>
          {visibleVideos.length === 0 ? (
            <p style={{ color: '#9ca3af', marginBottom: 0 }}>No videos in this filter yet.</p>
          ) : (
            pagedVideos.map((video) => (
              <VideoCard
                key={video.id}
                video={video}
                allowDelete={isOwnCreatorPage}
                onDeleted={handleVideoDeleted}
              />
            ))
          )}

          {visibleVideos.length > PAGE_SIZE ? (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 8 }}>
              <button
                type="button"
                onClick={() => setPage((prev) => Math.max(1, prev - 1))}
                disabled={page <= 1}
                style={{ border: '1px solid #374151', borderRadius: 8, background: '#111827', color: '#fff', padding: '6px 10px' }}
              >
                Previous
              </button>
              <span style={{ color: '#9ca3af', fontSize: 12 }}>Page {page} / {totalPages}</span>
              <button
                type="button"
                onClick={() => setPage((prev) => Math.min(totalPages, prev + 1))}
                disabled={page >= totalPages}
                style={{ border: '1px solid #374151', borderRadius: 8, background: '#111827', color: '#fff', padding: '6px 10px' }}
              >
                Next
              </button>
            </div>
          ) : null}
        </section>
      )}
    </main>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div style={{ border: '1px solid #1f2937', borderRadius: 10, padding: '8px 10px', background: '#0b1220' }}>
      <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>{label}</p>
      <p style={{ margin: '2px 0 0', fontSize: 18, fontWeight: 700 }}>{value.toLocaleString()}</p>
    </div>
  );
}

function FilterButton({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        border: '1px solid #374151',
        borderRadius: 999,
        padding: '6px 12px',
        background: active ? '#111827' : 'transparent',
        color: '#fff',
        cursor: 'pointer',
      }}
    >
      {label}
    </button>
  );
}
