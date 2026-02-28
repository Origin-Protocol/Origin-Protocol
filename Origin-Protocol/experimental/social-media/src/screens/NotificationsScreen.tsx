import { FormEvent, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { messagingApi } from '../api/client';
import { AppNotification, NotificationSettings } from '../types';
import { useAuth } from '../hooks/useAuth';

const TYPE_LABELS: Record<string, string> = {
  dm: 'Direct message',
  video_like: 'Video like',
  video_comment: 'Video comment',
  comment_reply: 'Comment reply',
  social_status: 'Social status',
  creator_upload: 'Creator upload',
  broadcast_post: 'Broadcast post',
  conversation_reply: 'Conversation reply',
  system: 'System',
  events: 'Events',
};

function whyText(item: AppNotification): string {
  switch (item.type) {
    case 'dm':
      return 'You received this because someone sent you a direct message.';
    case 'video_like':
      return 'You received this because someone liked one of your videos.';
    case 'video_comment':
      return 'You received this because someone commented on one of your videos.';
    case 'comment_reply':
      return 'You received this because someone replied to you or mentioned your username in a comment.';
    case 'social_status':
      return 'You received this because this is a status update for your own creator activity.';
    case 'creator_upload':
      return 'You received this because you enabled upload notifications for this creator.';
    case 'broadcast_post':
      return 'You received this because you subscribed to this creator channel or enabled broadcast notifications.';
    case 'conversation_reply':
      return 'You received this because you are part of that conversation.';
    case 'system':
      return 'You received this because your account has an important system or security update.';
    case 'events':
      return 'You received this because event notifications are enabled in your preferences.';
    default:
      return 'You received this based on your current notification preferences.';
  }
}

function destinationFor(item: AppNotification): string {
  const videoId = item.data?.videoId;
  const hasComment = Boolean(item.data?.commentId);
  if (videoId) {
    return hasComment ? `/video/${videoId}?comments=1` : `/video/${videoId}`;
  }

  if (item.type === 'dm' || item.type === 'conversation_reply' || item.type === 'broadcast_post') {
    const conversationId = item.data?.conversationId;
    return conversationId ? `/messages?conversationId=${encodeURIComponent(conversationId)}` : '/messages';
  }
  return '/feed';
}

function relative(iso: string): string {
  const delta = Date.now() - Date.parse(iso);
  const mins = Math.floor(delta / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  const days = Math.floor(hrs / 24);
  return `${days}d`;
}

export default function NotificationsScreen() {
  const { user } = useAuth();
  const [items, setItems] = useState<AppNotification[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [unreadCount, setUnreadCount] = useState(0);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [typeFilter, setTypeFilter] = useState<'all' | keyof typeof TYPE_LABELS>('all');
  const [expandedWhyId, setExpandedWhyId] = useState<string | null>(null);
  const [settings, setSettings] = useState<NotificationSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load(firstPage = true) {
    const res = await messagingApi.listNotifications(firstPage ? undefined : cursor ?? undefined, 30, unreadOnly);
    if (firstPage) {
      setItems(res.items);
    } else {
      setItems((prev) => [...prev, ...res.items]);
    }
    setCursor(res.nextCursor);
    setUnreadCount(res.unreadCount);
  }

  useEffect(() => {
    if (!user) {
      setItems([]);
      setCursor(null);
      setUnreadCount(0);
      setSettings(null);
      setLoading(false);
      return;
    }

    let cancelled = false;
    let pollInFlight = false;

    async function init() {
      setLoading(true);
      setError(null);
      try {
        const [notifRes, settingsRes] = await Promise.all([
          messagingApi.listNotifications(undefined, 30, unreadOnly),
          messagingApi.getNotificationSettings(),
        ]);
        if (cancelled) return;
        setItems(notifRes.items);
        setCursor(notifRes.nextCursor);
        setUnreadCount(notifRes.unreadCount);
        setSettings(settingsRes.settings);
      } catch (err) {
        if (!cancelled) setError((err as Error).message || 'Failed to load notifications.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void init();

    const timer = window.setInterval(() => {
      if (document.hidden || pollInFlight) return;
      pollInFlight = true;
      void load(true).catch(() => {
        // polling fallback
      }).finally(() => {
        pollInFlight = false;
      });
    }, 45_000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [user?.id, unreadOnly]);

  async function markRead(id: string) {
    try {
      await messagingApi.markNotificationRead(id);
      await load(true);
    } catch (err) {
      setError((err as Error).message || 'Unable to mark notification read.');
    }
  }

  async function markAllRead() {
    try {
      await messagingApi.markAllNotificationsRead();
      await load(true);
    } catch (err) {
      setError((err as Error).message || 'Unable to mark all read.');
    }
  }

  async function saveSettings(e: FormEvent) {
    e.preventDefault();
    if (!settings) return;
    try {
      const res = await messagingApi.updateNotificationSettings({
        categories: settings.categories,
        quietHours: settings.quietHours,
        experience: settings.experience,
      });
      setSettings(res.settings);
    } catch (err) {
      setError((err as Error).message || 'Unable to save settings.');
    }
  }

  async function toggleWhyHints() {
    if (!settings) return;
    const next = !settings.experience.showWhyHints;
    try {
      const res = await messagingApi.updateNotificationSettings({
        experience: {
          showWhyHints: next,
        },
      });
      setSettings(res.settings);
      if (!res.settings.experience.showWhyHints) {
        setExpandedWhyId(null);
      }
    } catch (err) {
      setError((err as Error).message || 'Unable to update preference.');
    }
  }

  if (!user) {
    return <main style={{ maxWidth: 900, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>Sign in to view notifications.</main>;
  }

  const visibleItems = typeFilter === 'all'
    ? items
    : items.filter((item) => item.type === typeFilter);

  return (
    <main style={{ maxWidth: 980, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>
      <h2 style={{ marginBottom: 6 }}>Notifications</h2>
      <p style={{ marginTop: 0, color: '#9ca3af' }}>Unread: {unreadCount}</p>
      {error ? <p style={{ color: '#fca5a5' }}>{error}</p> : null}

      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10, marginBottom: 10 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <button type="button" onClick={() => setUnreadOnly((v) => !v)}>{unreadOnly ? 'Show all' : 'Show unread only'}</button>
          <button type="button" onClick={() => void markAllRead()}>Mark all read</button>
          <button
            type="button"
            onClick={() => void toggleWhyHints()}
            disabled={!settings}
          >
            {settings?.experience.showWhyHints ? "Don't show this again" : 'Show why links'}
          </button>
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value as 'all' | keyof typeof TYPE_LABELS)}>
            <option value="all">All types</option>
            {Object.entries(TYPE_LABELS).map(([value, label]) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </div>
      </section>

      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10, marginBottom: 10 }}>
        <h3 style={{ marginTop: 0 }}>Notification preferences</h3>
        {!settings ? (
          <p style={{ color: '#9ca3af' }}>Loading settings…</p>
        ) : (
          <form onSubmit={(e) => void saveSettings(e)} style={{ display: 'grid', gap: 8 }}>
            {Object.entries(settings.categories).map(([key, value]) => (
              <label key={key} style={{ display: 'grid', gap: 4 }}>
                <span style={{ textTransform: 'capitalize' }}>{key.replace(/_/g, ' ')}</span>
                <select
                  value={value}
                  onChange={(e) => setSettings((prev) => prev ? {
                    ...prev,
                    categories: {
                      ...prev.categories,
                      [key]: e.target.value as 'in_app' | 'in_app_push' | 'off',
                    },
                  } : prev)}
                >
                  <option value="in_app">In-app only</option>
                  <option value="in_app_push">In-app + push</option>
                  <option value="off">Off</option>
                </select>
              </label>
            ))}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 8 }}>
              <label>Quiet start hour
                <input
                  type="number"
                  min={0}
                  max={23}
                  value={settings.quietHours.startHour}
                  onChange={(e) => setSettings((prev) => prev ? {
                    ...prev,
                    quietHours: { ...prev.quietHours, startHour: Number(e.target.value) || 0 },
                  } : prev)}
                />
              </label>
              <label>Quiet end hour
                <input
                  type="number"
                  min={0}
                  max={23}
                  value={settings.quietHours.endHour}
                  onChange={(e) => setSettings((prev) => prev ? {
                    ...prev,
                    quietHours: { ...prev.quietHours, endHour: Number(e.target.value) || 8 },
                  } : prev)}
                />
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <input
                  type="checkbox"
                  checked={settings.quietHours.enabled}
                  onChange={(e) => setSettings((prev) => prev ? {
                    ...prev,
                    quietHours: { ...prev.quietHours, enabled: e.target.checked },
                  } : prev)}
                />
                Quiet mode
              </label>
            </div>
            <button type="submit">Save preferences</button>
          </form>
        )}
      </section>

      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10 }}>
        <h3 style={{ marginTop: 0 }}>Notification center</h3>
        {loading ? <p style={{ color: '#9ca3af' }}>Loading…</p> : null}
        <div style={{ display: 'grid', gap: 8 }}>
          {visibleItems.map((item) => (
            <article key={item.id} style={{ border: '1px solid #1f2937', borderRadius: 10, padding: 10, background: item.readAt ? '#0f172a' : '#111827' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <strong>{item.title}</strong>
                <span style={{ color: '#9ca3af', fontSize: 12 }}>{relative(item.createdAt)}</span>
              </div>
              <p style={{ margin: '4px 0 0', color: '#cbd5e1' }}>{item.body}</p>
              <p style={{ margin: '4px 0 0', color: '#64748b', fontSize: 12 }}>{TYPE_LABELS[item.type] || item.type}</p>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 6, flexWrap: 'wrap' }}>
                <Link to={destinationFor(item)} style={{ color: '#93c5fd', fontSize: 12 }}>Open related item</Link>
                {settings?.experience.showWhyHints ? (
                  <button
                    type="button"
                    onClick={() => setExpandedWhyId((prev) => (prev === item.id ? null : item.id))}
                    style={{ fontSize: 12, color: '#93c5fd', background: 'transparent', border: 'none', padding: 0, cursor: 'pointer' }}
                  >
                    Why you got this
                  </button>
                ) : null}
              </div>
              {settings?.experience.showWhyHints && expandedWhyId === item.id ? (
                <p style={{ margin: '6px 0 0', color: '#9ca3af', fontSize: 12 }}>{whyText(item)}</p>
              ) : null}
              {!item.readAt ? (
                <button type="button" onClick={() => void markRead(item.id)} style={{ marginTop: 6 }}>Mark read</button>
              ) : null}
            </article>
          ))}
        </div>
        {cursor ? (
          <button type="button" onClick={() => void load(false)} style={{ marginTop: 10 }}>Load more</button>
        ) : null}
      </section>
    </main>
  );
}
