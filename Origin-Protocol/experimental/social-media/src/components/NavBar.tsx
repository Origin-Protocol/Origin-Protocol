import { Link, useLocation } from 'react-router-dom';
import { useEffect, useRef, useState } from 'react';
import { liveApi, membershipApi, messagingApi, usersApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import type { Conversation, User } from '../types';
import RecentConversationRow from './messaging/RecentConversationRow';

export default function NavBar() {
  const { user } = useAuth();
  const { pathname } = useLocation();
  const [isAdmin, setIsAdmin] = useState(false);
  const [showLiveNav, setShowLiveNav] = useState(false);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [unreadMessages, setUnreadMessages] = useState(0);
  const [notifOpen, setNotifOpen] = useState(false);
  const [messagesOpen, setMessagesOpen] = useState(false);
  const [recentNotifications, setRecentNotifications] = useState<Array<{ id: string; title: string; createdAt: string; readAt?: string }>>([]);
  const [recentConversations, setRecentConversations] = useState<Conversation[]>([]);
  const [conversationProfiles, setConversationProfiles] = useState<Record<string, User>>({});
  const [notifLoading, setNotifLoading] = useState(false);
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [compact, setCompact] = useState<boolean>(() => window.innerWidth <= 980);
  const notifMenuRef = useRef<HTMLDivElement | null>(null);
  const messagesMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function checkAdmin() {
      if (!user) {
        setIsAdmin(false);
        return;
      }
      try {
        const status = await membershipApi.status();
        if (!cancelled) setIsAdmin(Boolean(status.isAdmin));
      } catch {
        if (!cancelled) setIsAdmin(false);
      }
    }

    void checkAdmin();
    return () => {
      cancelled = true;
    };
  }, [user?.id]);

  useEffect(() => {
    let cancelled = false;

    async function refreshLiveUnlock() {
      if (!user || pathname === '/live' || pathname.startsWith('/live/')) {
        if (!cancelled) setShowLiveNav(false);
        return;
      }

      try {
        const eligibility = await liveApi.getEligibility();
        if (!cancelled) {
          setShowLiveNav(Boolean(eligibility.eligible || eligibility.activeSession));
        }
      } catch {
        if (!cancelled) setShowLiveNav(false);
      }
    }

    void refreshLiveUnlock();
    const timer = window.setInterval(() => {
      void refreshLiveUnlock();
    }, 60_000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [user?.id, pathname]);

  useEffect(() => {
    let cancelled = false;

    async function refreshUnread() {
      if (!user || document.hidden || pathname === '/notifications') return;
      try {
        const res = await messagingApi.listNotifications(undefined, 1, true);
        if (!cancelled) {
          setUnreadNotifications(res.unreadCount);
        }
      } catch {
        if (!cancelled) setUnreadNotifications((prev) => prev);
      }
    }

    void refreshUnread();
    const timer = window.setInterval(() => {
      void refreshUnread();
    }, 60_000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [user?.id, pathname]);

  useEffect(() => {
    let cancelled = false;

    async function refreshMessagesUnread() {
      if (!user || document.hidden || pathname === '/messages') return;
      try {
        const res = await messagingApi.listConversations();
        const unread = res.items.reduce((sum, item) => sum + (item.unreadCount ?? item.memberState?.unreadCount ?? 0), 0);
        if (!cancelled) setUnreadMessages(unread);
      } catch {
        if (!cancelled) setUnreadMessages((prev) => prev);
      }
    }

    void refreshMessagesUnread();
    const timer = window.setInterval(() => {
      void refreshMessagesUnread();
    }, 60_000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [user?.id, pathname]);

  const active = (path: string) =>
    (path === '/profile'
      ? pathname.startsWith('/profile')
      : path === '/live'
        ? pathname === '/live' || pathname.startsWith('/live/')
      : path === '/profile'
        ? pathname === '/profile' || pathname.startsWith('/profile')
      : path === '/'
        ? pathname === '/' || pathname === '/feed'
        : pathname === path)
      ? { fontWeight: 'bold' as const, color: '#fff', textShadow: '0 0 16px rgba(167,139,250,0.8)' }
      : { color: '#cbd5e1' };

  useEffect(() => {
    if (!notifOpen) return;
    if (!user) return;
    let cancelled = false;

    async function loadRecentNotifications() {
      setNotifLoading(true);
      try {
        const res = await messagingApi.listNotifications(undefined, 8, false);
        if (!cancelled) {
          setRecentNotifications(res.items.map((item) => ({
            id: item.id,
            title: item.title,
            createdAt: item.createdAt,
            readAt: item.readAt,
          })));
        }
      } catch {
        if (!cancelled) setRecentNotifications([]);
      } finally {
        if (!cancelled) setNotifLoading(false);
      }
    }

    void loadRecentNotifications();
    return () => {
      cancelled = true;
    };
  }, [notifOpen]);

  useEffect(() => {
    if (!messagesOpen || !user) return;
    const currentUserId = user.id;
    let cancelled = false;

    async function loadRecentConversations() {
      setMessagesLoading(true);
      try {
        const res = await messagingApi.listConversations();
        const items = [...res.items]
          .sort((a, b) => {
            const aUnread = a.unreadCount ?? a.memberState?.unreadCount ?? 0;
            const bUnread = b.unreadCount ?? b.memberState?.unreadCount ?? 0;
            if (aUnread !== bUnread) return bUnread - aUnread;
            return (b.lastMessageAt ?? b.updatedAt).localeCompare(a.lastMessageAt ?? a.updatedAt);
          })
          .slice(0, 8);

        if (cancelled) return;
        setRecentConversations(items);

        const candidateIds = items
          .map((conversation) => {
            if (conversation.type === 'broadcast') return conversation.ownerUserId || '';
            return conversation.participantIds.find((id) => id !== currentUserId) || '';
          })
          .filter(Boolean);

        const uniqueIds = [...new Set(candidateIds)];
        if (uniqueIds.length === 0) {
          setConversationProfiles({});
          return;
        }

        const profileResults = await Promise.all(
          uniqueIds.map(async (id) => {
            try {
              const response = await usersApi.getProfile(id);
              return response.user;
            } catch {
              return null;
            }
          })
        );

        if (cancelled) return;

        const mapped: Record<string, User> = {};
        for (const profile of profileResults) {
          if (profile) mapped[profile.id] = profile;
        }
        setConversationProfiles(mapped);
      } catch {
        if (!cancelled) {
          setRecentConversations([]);
          setConversationProfiles({});
        }
      } finally {
        if (!cancelled) setMessagesLoading(false);
      }
    }

    void loadRecentConversations();
    return () => {
      cancelled = true;
    };
  }, [messagesOpen, user]);

  useEffect(() => {
    const onResize = () => setCompact(window.innerWidth <= 980);
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
    };
  }, []);

  useEffect(() => {
    function onDocumentClick(event: MouseEvent) {
      if (!notifMenuRef.current) return;
      const target = event.target as Node | null;
      if (target && !notifMenuRef.current.contains(target)) {
        setNotifOpen(false);
      }

      if (messagesMenuRef.current && target && !messagesMenuRef.current.contains(target)) {
        setMessagesOpen(false);
      }
    }

    if (notifOpen || messagesOpen) {
      document.addEventListener('mousedown', onDocumentClick);
    }

    return () => {
      document.removeEventListener('mousedown', onDocumentClick);
    };
  }, [notifOpen, messagesOpen]);

  function relative(iso: string): string {
    const delta = Date.now() - Date.parse(iso);
    const mins = Math.floor(delta / 60_000);
    if (mins < 1) return 'now';
    if (mins < 60) return `${mins}m`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h`;
    return `${Math.floor(hrs / 24)}d`;
  }

  if (!user) {
    return null;
  }

  return (
    <nav style={{
      position: 'fixed', bottom: 0, left: 0, right: 0,
      display: 'flex', justifyContent: compact ? 'flex-start' : 'space-around',
      gap: compact ? 12 : 8,
      overflowX: compact ? 'auto' : 'visible',
      whiteSpace: 'nowrap',
      padding: '10px 8px', background: 'rgba(2,6,23,0.92)', borderTop: '1px solid #1f2937',
      zIndex: 100,
      backdropFilter: 'blur(8px)',
    }}>
      <Link to="/" style={{ ...active('/'), textDecoration: 'none' }}>{compact ? '🏠' : '🏠 Feed'}</Link>
      <Link to="/profile" style={{ ...active('/profile'), textDecoration: 'none' }}>{compact ? '⚙️' : '⚙️ Settings'}</Link>
      <Link to="/abigail" style={{ ...active('/abigail'), textDecoration: 'none' }}>{compact ? '🧠' : '🧠 Abigail'}</Link>
      {showLiveNav ? <Link to="/live" style={{ ...active('/live'), textDecoration: 'none' }}>{compact ? '🔴' : '🔴 Live'}</Link> : null}
      <div ref={messagesMenuRef} style={{ position: 'relative' }}>
        <button
          type="button"
          onClick={() => setMessagesOpen((prev) => !prev)}
          style={{
            ...active('/messages'),
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            position: 'relative',
            fontSize: 15,
          }}
          aria-label="Open messages menu"
        >
          {compact ? '💬' : '💬 Messages'}
          {unreadMessages > 0 ? (
            <span
              style={{
                position: 'absolute',
                top: -8,
                right: -14,
                minWidth: 18,
                borderRadius: 999,
                background: '#2563eb',
                color: '#fff',
                fontSize: 11,
                textAlign: 'center',
                padding: '1px 5px',
              }}
            >
              {unreadMessages > 99 ? '99+' : unreadMessages}
            </span>
          ) : null}
        </button>

        {messagesOpen ? (
          <div
            style={{
              position: 'absolute',
              bottom: 42,
              right: compact ? -8 : -24,
              width: 330,
              maxHeight: 360,
              overflowY: 'auto',
              border: '1px solid #1f2937',
              borderRadius: 10,
              background: '#020617',
              boxShadow: '0 10px 40px rgba(0,0,0,0.35)',
              padding: 8,
              zIndex: 130,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <strong style={{ color: '#e5e7eb' }}>Messages</strong>
              <Link to="/messages" onClick={() => setMessagesOpen(false)} style={{ color: '#93c5fd', fontSize: 12 }}>
                Open inbox
              </Link>
            </div>
            {messagesLoading ? <p style={{ margin: 0, color: '#94a3b8', fontSize: 12 }}>Loading…</p> : null}
            {!messagesLoading && recentConversations.length === 0 ? (
              <p style={{ margin: 0, color: '#94a3b8', fontSize: 12 }}>No conversations yet.</p>
            ) : null}
            <div style={{ display: 'grid', gap: 6 }}>
              {recentConversations.map((conversation) => {
                const peerId = conversation.type === 'broadcast'
                  ? conversation.ownerUserId || ''
                  : conversation.participantIds.find((id) => id !== user.id) || '';
                const peer = peerId ? conversationProfiles[peerId] : null;
                const unreadCount = conversation.unreadCount ?? conversation.memberState?.unreadCount ?? 0;

                return (
                  <RecentConversationRow
                    key={conversation.id}
                    conversationId={conversation.id}
                    title={peer?.displayName || conversation.title || `${conversation.type.toUpperCase()} • ${conversation.id.slice(0, 8)}`}
                    snippet={conversation.lastMessagePreview || 'No messages yet'}
                    unreadCount={unreadCount}
                    timestamp={relative(conversation.lastMessageAt || conversation.updatedAt)}
                    counterparty={peer}
                    onNavigate={() => setMessagesOpen(false)}
                  />
                );
              })}
            </div>
          </div>
        ) : null}
      </div>
      <div ref={notifMenuRef} style={{ position: 'relative' }}>
        <button
          type="button"
          onClick={() => setNotifOpen((prev) => !prev)}
          style={{
            ...active('/notifications'),
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            position: 'relative',
            fontSize: 15,
          }}
          aria-label="Open notifications menu"
        >
          {compact ? '🔔' : '🔔 Notifications'}
          {unreadNotifications > 0 ? (
            <span
              style={{
                position: 'absolute',
                top: -8,
                right: -14,
                minWidth: 18,
                borderRadius: 999,
                background: '#ef4444',
                color: '#fff',
                fontSize: 11,
                textAlign: 'center',
                padding: '1px 5px',
              }}
            >
              {unreadNotifications > 99 ? '99+' : unreadNotifications}
            </span>
          ) : null}
        </button>

        {notifOpen ? (
          <div
            style={{
              position: 'absolute',
              bottom: 42,
              right: -24,
              width: 310,
              maxHeight: 340,
              overflowY: 'auto',
              border: '1px solid #1f2937',
              borderRadius: 10,
              background: '#020617',
              boxShadow: '0 10px 40px rgba(0,0,0,0.35)',
              padding: 8,
              zIndex: 120,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <strong style={{ color: '#e5e7eb' }}>Notifications</strong>
              <Link to="/notifications" onClick={() => setNotifOpen(false)} style={{ color: '#93c5fd', fontSize: 12 }}>
                Open page
              </Link>
            </div>
            {notifLoading ? <p style={{ margin: 0, color: '#94a3b8', fontSize: 12 }}>Loading…</p> : null}
            {!notifLoading && recentNotifications.length === 0 ? (
              <p style={{ margin: 0, color: '#94a3b8', fontSize: 12 }}>No notifications.</p>
            ) : null}
            <div style={{ display: 'grid', gap: 6 }}>
              {recentNotifications.map((item) => (
                <Link
                  key={item.id}
                  to="/notifications"
                  onClick={() => setNotifOpen(false)}
                  style={{
                    textDecoration: 'none',
                    border: '1px solid #1f2937',
                    borderRadius: 8,
                    background: item.readAt ? '#0b1220' : '#111827',
                    padding: '7px 8px',
                    color: '#e5e7eb',
                  }}
                >
                  <p style={{ margin: 0, fontSize: 12 }}>{item.title}</p>
                  <p style={{ margin: '3px 0 0', fontSize: 11, color: '#94a3b8' }}>{relative(item.createdAt)}</p>
                </Link>
              ))}
            </div>
          </div>
        ) : null}
      </div>
      {isAdmin && <Link to="/admin" style={{ ...active('/admin'), textDecoration: 'none' }}>{compact ? '🛠️' : '🛠️ Admin'}</Link>}
      <Link to="/help" style={{ ...active('/help'), textDecoration: 'none' }}>{compact ? '❓' : '❓ Help'}</Link>
      <Link to={user ? '/profile' : '/login'} style={{ ...active('/profile'), textDecoration: 'none' }}>{compact ? '👤' : '👤 Me'}</Link>
    </nav>
  );
}
