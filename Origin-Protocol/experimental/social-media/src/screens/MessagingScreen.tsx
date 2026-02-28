import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { messagingApi, usersApi } from '../api/client';
import { Conversation, ConversationMessage, User } from '../types';
import { useAuth } from '../hooks/useAuth';
import ConversationSidebarItem from '../components/messaging/ConversationSidebarItem';
import MessageBubble from '../components/messaging/MessageBubble';
import { profileHref } from '../components/messaging/profileLink';

const SUBSCRIPTIONS_KEY = 'origin_creator_subscriptions_v1';

type TypingMap = Record<string, Record<string, number>>;

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return '—';
  const delta = Date.now() - Date.parse(iso);
  if (!Number.isFinite(delta)) return '—';
  const minutes = Math.floor(delta / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

function sortConversations(items: Conversation[]): Conversation[] {
  return [...items].sort((a, b) => {
    const aPinned = Boolean(a.memberState?.pinned);
    const bPinned = Boolean(b.memberState?.pinned);
    if (aPinned !== bPinned) return aPinned ? -1 : 1;

    const aUnread = a.unreadCount ?? a.memberState?.unreadCount ?? 0;
    const bUnread = b.unreadCount ?? b.memberState?.unreadCount ?? 0;
    if (aUnread !== bUnread) return bUnread - aUnread;

    const aTs = a.lastMessageAt ?? a.updatedAt;
    const bTs = b.lastMessageAt ?? b.updatedAt;
    return bTs.localeCompare(aTs);
  });
}

function normalizeMessage(item: ConversationMessage): ConversationMessage {
  return {
    ...item,
    sentAt: item.sentAt ?? item.createdAt,
    deliveredTo: Array.isArray(item.deliveredTo) ? item.deliveredTo : [],
    readBy: Array.isArray(item.readBy) ? item.readBy : [],
  };
}

export default function MessagingScreen() {
  const [searchParams] = useSearchParams();
  const { user } = useAuth();

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string>('');
  const [messages, setMessages] = useState<ConversationMessage[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [draft, setDraft] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newDmUserId, setNewDmUserId] = useState('');
  const [newBroadcastTitle, setNewBroadcastTitle] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchBusy, setSearchBusy] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searchResults, setSearchResults] = useState<User[]>([]);
  const [suggestedPeople, setSuggestedPeople] = useState<User[]>([]);
  const [profilesById, setProfilesById] = useState<Record<string, User>>({});
  const [typingMap, setTypingMap] = useState<TypingMap>({});
  const [isMobile, setIsMobile] = useState<boolean>(() => window.innerWidth < 900);

  const typingHeartbeatRef = useRef<number | null>(null);
  const typingStateRef = useRef<{ conversationId: string; typing: boolean }>({ conversationId: '', typing: false });
  const messagesScrollRef = useRef<HTMLDivElement | null>(null);
  const shouldStickToBottomRef = useRef(true);
  const forceScrollNextRef = useRef(false);
  const lastSeenMessageIdRef = useRef<string | null>(null);

  const [pendingIncomingCount, setPendingIncomingCount] = useState(0);

  const activeConversation = useMemo(
    () => conversations.find((item) => item.id === activeConversationId) ?? null,
    [conversations, activeConversationId]
  );

  const subscribedCreatorIds = useMemo(() => {
    try {
      const raw = window.localStorage.getItem(SUBSCRIPTIONS_KEY);
      const parsed = raw ? (JSON.parse(raw) as Record<string, boolean>) : {};
      return new Set(Object.entries(parsed).filter(([, value]) => Boolean(value)).map(([id]) => id));
    } catch {
      return new Set<string>();
    }
  }, []);

  function getCounterpartyId(conversation: Conversation): string | null {
    if (!user) return null;

    if (conversation.type === 'broadcast') {
      return conversation.ownerUserId ?? null;
    }

    const peers = conversation.participantIds.filter((participantId) => participantId !== user.id);
    return peers[0] ?? null;
  }

  function getConversationTitle(conversation: Conversation): string {
    const peerId = getCounterpartyId(conversation);
    const peer = peerId ? profilesById[peerId] : null;
    if (conversation.type === 'dm' && peer) {
      return peer.displayName || `@${peer.username}`;
    }
    return conversation.title || `${conversation.type.toUpperCase()} • ${conversation.id.slice(0, 8)}`;
  }

  function getConversationRelationship(conversation: Conversation): 'friend' | 'subscriber' | 'creator' | 'group' {
    if (conversation.type === 'group') return 'group';
    if (conversation.type === 'broadcast') return 'subscriber';

    const peerId = getCounterpartyId(conversation);
    const peer = peerId ? profilesById[peerId] : null;

    if (peer?.creatorKeyId) return 'creator';
    if (peerId && subscribedCreatorIds.has(peerId)) return 'subscriber';
    return 'friend';
  }

  function getTypingUsers(conversationId: string): User[] {
    const entries = typingMap[conversationId] ?? {};
    const now = Date.now();
    return Object.entries(entries)
      .filter(([, ts]) => now - ts < 7000)
      .map(([userId]) => profilesById[userId])
      .filter((item): item is User => Boolean(item));
  }

  async function hydrateUserProfiles(userIds: string[]) {
    const deduped = [...new Set(userIds.filter(Boolean))].filter((id) => !profilesById[id]);
    if (deduped.length === 0) return;

    const results = await Promise.all(
      deduped.map(async (id) => {
        try {
          const res = await usersApi.getProfile(id);
          return res.user;
        } catch {
          return null;
        }
      })
    );

    const updates: Record<string, User> = {};
    for (const profile of results) {
      if (profile) updates[profile.id] = profile;
    }

    if (Object.keys(updates).length > 0) {
      setProfilesById((prev) => ({ ...prev, ...updates }));
    }
  }

  async function loadConversations(preferredConversationId?: string) {
    const res = await messagingApi.listConversations();
    const sorted = sortConversations(res.items);
    setConversations(sorted);

    setActiveConversationId((prev) => {
      const focus = preferredConversationId || prev;
      if (focus && sorted.some((conversation) => conversation.id === focus)) return focus;
      return sorted[0]?.id ?? '';
    });

    const idsToHydrate: string[] = [];
    for (const conversation of sorted) {
      const peerId = getCounterpartyId(conversation);
      if (peerId) idsToHydrate.push(peerId);
      if (conversation.ownerUserId) idsToHydrate.push(conversation.ownerUserId);
    }
    await hydrateUserProfiles(idsToHydrate);
  }

  async function loadMessages(conversationId: string, cursor?: string) {
    const res = await messagingApi.listMessages(conversationId, cursor, 40);
    const nextItems = res.items.map(normalizeMessage);
    if (cursor) {
      setMessages((prev) => [...nextItems, ...prev]);
    } else {
      setMessages(nextItems);
    }
    setNextCursor(res.nextCursor);

    await hydrateUserProfiles(nextItems.map((item) => item.senderId));
  }

  useEffect(() => {
    const focusConversationId = searchParams.get('conversationId')?.trim();
    if (!focusConversationId) return;
    setActiveConversationId(focusConversationId);
  }, [searchParams]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const focusConversationId = searchParams.get('conversationId')?.trim();
        await loadConversations(focusConversationId);
      } catch (err) {
        if (!cancelled) setError((err as Error).message || 'Failed to load conversations.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!activeConversationId) {
      setMessages([]);
      setNextCursor(null);
      setPendingIncomingCount(0);
      lastSeenMessageIdRef.current = null;
      return;
    }

    let cancelled = false;

    async function hydrateConversation() {
      try {
        forceScrollNextRef.current = true;
        setPendingIncomingCount(0);
        lastSeenMessageIdRef.current = null;
        await loadMessages(activeConversationId);
        await messagingApi.markConversationRead(activeConversationId);
        setConversations((prev) =>
          prev.map((conversation) =>
            conversation.id === activeConversationId
              ? {
                  ...conversation,
                  unreadCount: 0,
                  memberState: conversation.memberState
                    ? {
                        ...conversation.memberState,
                        unreadCount: 0,
                        lastReadAt: new Date().toISOString(),
                      }
                    : conversation.memberState,
                }
              : conversation
          )
        );
      } catch (err) {
        if (!cancelled) setError((err as Error).message || 'Failed to load messages.');
      }
    }

    void hydrateConversation();

    return () => {
      cancelled = true;
    };
  }, [activeConversationId]);

  useEffect(() => {
    if (!user) return;

    let mounted = true;
    const source = new EventSource(messagingApi.eventsUrl());

    function safeParse(raw: string) {
      try {
        return JSON.parse(raw) as any;
      } catch {
        return null;
      }
    }

    source.addEventListener('message', (event) => {
      const payload = safeParse((event as MessageEvent<string>).data);
      if (!payload?.conversationId || !payload?.message) return;

      const incoming = normalizeMessage(payload.message as ConversationMessage);

      setConversations((prev) => {
        const next = prev.map((conversation) => {
          if (conversation.id !== payload.conversationId) return conversation;
          const unreadCount = payload.conversationId === activeConversationId
            ? 0
            : (conversation.unreadCount ?? conversation.memberState?.unreadCount ?? 0) + 1;
          return {
            ...conversation,
            lastMessageAt: incoming.createdAt,
            updatedAt: incoming.createdAt,
            lastMessagePreview: incoming.content?.slice(0, 220) || '[media]',
            unreadCount,
            memberState: conversation.memberState
              ? { ...conversation.memberState, unreadCount }
              : conversation.memberState,
          };
        });
        return sortConversations(next);
      });

      if (payload.conversationId === activeConversationId) {
        setMessages((prev) => {
          if (prev.some((item) => item.id === incoming.id)) return prev;
          return [...prev, incoming];
        });
      }

      void hydrateUserProfiles([incoming.senderId]);
    });

    source.addEventListener('message:sent', () => {
      void loadConversations(activeConversationId || undefined);
    });

    source.addEventListener('conversation:typing', (event) => {
      const payload = safeParse((event as MessageEvent<string>).data);
      if (!payload?.conversationId || !payload?.userId || payload.userId === user.id) return;

      setTypingMap((prev) => {
        const conversationTyping = { ...(prev[payload.conversationId] ?? {}) };
        if (payload.isTyping) {
          conversationTyping[payload.userId] = Date.now();
        } else {
          delete conversationTyping[payload.userId];
        }
        return {
          ...prev,
          [payload.conversationId]: conversationTyping,
        };
      });

      void hydrateUserProfiles([payload.userId]);
    });

    source.addEventListener('conversation:read', (event) => {
      const payload = safeParse((event as MessageEvent<string>).data);
      if (!payload?.conversationId || !payload?.userId || payload.conversationId !== activeConversationId) return;

      setMessages((prev) =>
        prev.map((message) => {
          if (message.senderId === payload.userId) return message;
          const readBy = Array.isArray(message.readBy) ? [...message.readBy] : [];
          if (!readBy.some((entry) => entry.userId === payload.userId)) {
            readBy.push({ userId: payload.userId, readAt: payload.ts || new Date().toISOString() });
          }
          return {
            ...message,
            readBy,
          };
        })
      );
    });

    source.onerror = () => {
      if (mounted) {
        // EventSource auto-reconnect handles transient disconnects.
      }
    };

    return () => {
      mounted = false;
      source.close();
    };
  }, [user, activeConversationId]);

  useEffect(() => {
    const cleanup = window.setInterval(() => {
      setTypingMap((prev) => {
        const now = Date.now();
        const next: TypingMap = {};

        for (const [conversationId, typingUsers] of Object.entries(prev)) {
          const filtered: Record<string, number> = {};
          for (const [userId, ts] of Object.entries(typingUsers)) {
            if (now - ts < 7000) {
              filtered[userId] = ts;
            }
          }
          if (Object.keys(filtered).length > 0) {
            next[conversationId] = filtered;
          }
        }

        return next;
      });
    }, 2500);

    return () => {
      window.clearInterval(cleanup);
    };
  }, []);

  useEffect(() => {
    const container = messagesScrollRef.current;
    if (!container) return;

    const latest = messages[messages.length - 1];
    if (latest && latest.id !== lastSeenMessageIdRef.current) {
      if (!shouldStickToBottomRef.current && !forceScrollNextRef.current && latest.senderId !== user?.id) {
        setPendingIncomingCount((count) => count + 1);
      }
      lastSeenMessageIdRef.current = latest.id;
    }

    if (!shouldStickToBottomRef.current && !forceScrollNextRef.current) {
      return;
    }

    container.scrollTo({
      top: container.scrollHeight,
      behavior: forceScrollNextRef.current ? 'auto' : 'smooth',
    });

    forceScrollNextRef.current = false;
    setPendingIncomingCount(0);
  }, [messages]);

  function handleMessagesScroll() {
    const container = messagesScrollRef.current;
    if (!container) return;

    const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
    shouldStickToBottomRef.current = distanceFromBottom < 120;
    if (shouldStickToBottomRef.current) {
      setPendingIncomingCount(0);
    }
  }

  function jumpToLatest() {
    const container = messagesScrollRef.current;
    if (!container) return;

    shouldStickToBottomRef.current = true;
    forceScrollNextRef.current = false;
    setPendingIncomingCount(0);
    container.scrollTo({ top: container.scrollHeight, behavior: 'smooth' });
  }

  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth < 900);
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
    };
  }, []);

  useEffect(() => {
    if (!activeConversationId || !user) return;

    const shouldType = draft.trim().length > 0;
    const previous = typingStateRef.current;

    if (previous.conversationId !== activeConversationId && previous.typing) {
      void messagingApi.setTyping(previous.conversationId, false).catch(() => undefined);
      typingStateRef.current = { conversationId: activeConversationId, typing: false };
    }

    if (!shouldType) {
      if (typingHeartbeatRef.current) {
        window.clearInterval(typingHeartbeatRef.current);
        typingHeartbeatRef.current = null;
      }
      if (typingStateRef.current.typing) {
        void messagingApi.setTyping(activeConversationId, false).catch(() => undefined);
      }
      typingStateRef.current = { conversationId: activeConversationId, typing: false };
      return;
    }

    if (!typingStateRef.current.typing || typingStateRef.current.conversationId !== activeConversationId) {
      void messagingApi.setTyping(activeConversationId, true).catch(() => undefined);
      typingStateRef.current = { conversationId: activeConversationId, typing: true };
    }

    if (!typingHeartbeatRef.current) {
      typingHeartbeatRef.current = window.setInterval(() => {
        if (!typingStateRef.current.typing) return;
        void messagingApi.setTyping(activeConversationId, true).catch(() => undefined);
      }, 4000);
    }

    return () => {
      if (typingHeartbeatRef.current) {
        window.clearInterval(typingHeartbeatRef.current);
        typingHeartbeatRef.current = null;
      }
      if (typingStateRef.current.typing) {
        void messagingApi.setTyping(activeConversationId, false).catch(() => undefined);
      }
      typingStateRef.current = { conversationId: activeConversationId, typing: false };
    };
  }, [draft, activeConversationId, user]);

  async function sendMessage(e: FormEvent) {
    e.preventDefault();
    if (!activeConversationId || !user) return;
    if (!draft.trim()) return;

    setSending(true);
    setError(null);

    try {
      const sent = await messagingApi.sendMessage(activeConversationId, { content: draft.trim() });
      const normalized = normalizeMessage(sent.message);
      setMessages((prev) => (prev.some((item) => item.id === normalized.id) ? prev : [...prev, normalized]));
      setDraft('');
      await messagingApi.setTyping(activeConversationId, false).catch(() => undefined);
      await loadConversations(activeConversationId);
    } catch (err) {
      setError((err as Error).message || 'Failed to send message.');
    } finally {
      setSending(false);
    }
  }

  async function react(messageId: string, emoji: string) {
    try {
      const res = await messagingApi.reactToMessage(messageId, emoji);
      const normalized = normalizeMessage(res.message);
      setMessages((prev) => prev.map((item) => (item.id === messageId ? normalized : item)));
    } catch (err) {
      setError((err as Error).message || 'Reaction failed.');
    }
  }

  async function createDm(e: FormEvent) {
    e.preventDefault();
    if (!newDmUserId.trim()) return;
    setError(null);

    try {
      const created = await messagingApi.createConversation({
        type: 'dm',
        participantIds: [newDmUserId.trim()],
      });
      setNewDmUserId('');
      await loadConversations(created.conversation.id);
      setActiveConversationId(created.conversation.id);
    } catch (err) {
      setError((err as Error).message || 'Unable to create DM.');
    }
  }

  async function startDmWithUser(userId: string) {
    setError(null);
    try {
      const created = await messagingApi.createConversation({
        type: 'dm',
        participantIds: [userId],
      });
      await loadConversations(created.conversation.id);
      setActiveConversationId(created.conversation.id);
    } catch (err) {
      setError((err as Error).message || 'Unable to create DM.');
    }
  }

  async function runUserSearch(e: FormEvent) {
    e.preventDefault();
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }

    setSearchBusy(true);
    setSearchError(null);
    try {
      const res = await usersApi.search(searchQuery.trim(), 12);
      setSearchResults(res.items);
      setProfilesById((prev) => {
        const updates: Record<string, User> = {};
        for (const person of res.items) {
          updates[person.id] = person;
        }
        return { ...prev, ...updates };
      });
    } catch (err) {
      setSearchError((err as Error).message || 'User search failed.');
    } finally {
      setSearchBusy(false);
    }
  }

  async function createBroadcast(e: FormEvent) {
    e.preventDefault();
    if (!newBroadcastTitle.trim()) return;
    setError(null);

    try {
      const created = await messagingApi.createConversation({
        type: 'broadcast',
        title: newBroadcastTitle.trim(),
        allowReplies: true,
      });
      setNewBroadcastTitle('');
      await loadConversations(created.conversation.id);
      setActiveConversationId(created.conversation.id);
    } catch (err) {
      setError((err as Error).message || 'Unable to create broadcast channel.');
    }
  }

  useEffect(() => {
    let cancelled = false;

    async function hydrateSuggestions() {
      try {
        const raw = window.localStorage.getItem(SUBSCRIPTIONS_KEY);
        const parsed = raw ? (JSON.parse(raw) as Record<string, boolean>) : {};
        const creatorIds = Object.entries(parsed)
          .filter(([, subscribed]) => Boolean(subscribed))
          .map(([creatorId]) => creatorId)
          .slice(0, 8);

        if (creatorIds.length === 0) {
          if (!cancelled) setSuggestedPeople([]);
          return;
        }

        const profiles = await Promise.all(
          creatorIds.map(async (creatorId) => {
            try {
              const res = await usersApi.getProfile(creatorId);
              return res.user;
            } catch {
              return null;
            }
          })
        );

        if (!cancelled) {
          const valid = profiles.filter((item): item is User => Boolean(item));
          setSuggestedPeople(valid);
          setProfilesById((prev) => {
            const updates: Record<string, User> = {};
            for (const person of valid) {
              updates[person.id] = person;
            }
            return { ...prev, ...updates };
          });
        }
      } catch {
        if (!cancelled) setSuggestedPeople([]);
      }
    }

    void hydrateSuggestions();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!user) {
    return <main style={{ maxWidth: 980, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>Sign in to use messaging.</main>;
  }

  const activeTypingUsers = activeConversation ? getTypingUsers(activeConversation.id) : [];

  return (
    <main style={{ maxWidth: 1200, margin: '0 auto', color: '#e5e7eb', padding: isMobile ? 8 : 12 }}>
      <h2 style={{ marginBottom: 6 }}>Messages</h2>
      <p style={{ marginTop: 0, color: '#9ca3af' }}>Real-time conversations with read state, receipts, and creator profile linking.</p>
      {error ? <p style={{ color: '#fca5a5' }}>{error}</p> : null}

      <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '340px 1fr', gap: isMobile ? 8 : 12 }}>
        <aside style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#020617', padding: isMobile ? 8 : 10, maxHeight: isMobile ? '42vh' : '76vh', overflow: 'auto' }}>
          <section style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0b1220', padding: 8, marginBottom: 10 }}>
            <h4 style={{ margin: '0 0 8px' }}>Message people</h4>
            <p style={{ margin: '0 0 8px', color: '#9ca3af', fontSize: 12 }}>
              Quickly message followers/subscribers, or search by user ID/username.
            </p>

            {suggestedPeople.length > 0 ? (
              <div style={{ display: 'grid', gap: 6, marginBottom: 8 }}>
                {suggestedPeople.map((person) => (
                  <button
                    key={person.id}
                    type="button"
                    onClick={() => void startDmWithUser(person.id)}
                    style={{ textAlign: 'left', border: '1px solid #1f2937', borderRadius: 8, background: '#0f172a', color: '#e5e7eb', padding: '6px 8px' }}
                  >
                    <strong>{person.displayName}</strong>
                    <span style={{ display: 'block', color: '#9ca3af', fontSize: 12 }}>@{person.username}</span>
                  </button>
                ))}
              </div>
            ) : (
              <p style={{ margin: '0 0 8px', color: '#9ca3af', fontSize: 12 }}>No subscribed people found yet.</p>
            )}

            <form onSubmit={(e) => void runUserSearch(e)} style={{ display: 'grid', gap: 6 }}>
              <input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by user ID, username, or nickname"
                style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, color: '#e5e7eb', padding: '8px 10px' }}
              />
              <button type="submit" disabled={searchBusy}>{searchBusy ? 'Searching…' : 'Find people'}</button>
            </form>
            {searchError ? <p style={{ color: '#fca5a5', fontSize: 12, margin: '6px 0 0' }}>{searchError}</p> : null}
            {searchResults.length > 0 ? (
              <div style={{ display: 'grid', gap: 6, marginTop: 8 }}>
                {searchResults.map((person) => (
                  <button
                    key={person.id}
                    type="button"
                    onClick={() => void startDmWithUser(person.id)}
                    style={{ textAlign: 'left', border: '1px solid #1f2937', borderRadius: 8, background: '#0f172a', color: '#e5e7eb', padding: '6px 8px' }}
                  >
                    <strong>{person.displayName}</strong>
                    <span style={{ display: 'block', color: '#9ca3af', fontSize: 12 }}>@{person.username} • {person.id.slice(0, 8)}</span>
                  </button>
                ))}
              </div>
            ) : null}
          </section>

          <form onSubmit={(e) => void createDm(e)} style={{ display: 'grid', gap: 6, marginBottom: 8 }}>
            <label style={{ fontSize: 12, color: '#9ca3af' }}>Start DM by user ID</label>
            <input
              value={newDmUserId}
              onChange={(e) => setNewDmUserId(e.target.value)}
              placeholder="userId"
              style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, color: '#e5e7eb', padding: '8px 10px' }}
            />
            <button type="submit">Create DM</button>
          </form>

          <form onSubmit={(e) => void createBroadcast(e)} style={{ display: 'grid', gap: 6, marginBottom: 10 }}>
            <label style={{ fontSize: 12, color: '#9ca3af' }}>Create broadcast channel</label>
            <input
              value={newBroadcastTitle}
              onChange={(e) => setNewBroadcastTitle(e.target.value)}
              placeholder="Channel title"
              style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, color: '#e5e7eb', padding: '8px 10px' }}
            />
            <button type="submit">Create channel</button>
          </form>

          {loading ? <p style={{ color: '#9ca3af' }}>Loading conversations…</p> : null}

          <div style={{ display: 'grid', gap: 8 }}>
            {conversations.map((conversation) => {
              const unreadCount = conversation.unreadCount ?? conversation.memberState?.unreadCount ?? 0;
              const peerId = getCounterpartyId(conversation);
              const peer = peerId ? profilesById[peerId] : null;

              return (
                <ConversationSidebarItem
                  key={conversation.id}
                  conversation={conversation}
                  active={activeConversationId === conversation.id}
                  unreadCount={unreadCount}
                  title={getConversationTitle(conversation)}
                  subtitle={conversation.lastMessagePreview || 'No messages yet'}
                  timestamp={formatRelative(conversation.lastMessageAt || conversation.updatedAt)}
                  relationship={getConversationRelationship(conversation)}
                  counterparty={peer}
                  onSelect={() => setActiveConversationId(conversation.id)}
                />
              );
            })}
          </div>
        </aside>

        <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#020617', padding: isMobile ? 8 : 10, display: 'grid', gridTemplateRows: 'auto 1fr auto', minHeight: isMobile ? '58vh' : '76vh', maxHeight: isMobile ? '68vh' : '76vh', overflow: 'hidden' }}>
          {!activeConversation ? (
            <p style={{ color: '#9ca3af' }}>Select a conversation.</p>
          ) : (
            <>
              <header style={{ borderBottom: '1px solid #1f2937', paddingBottom: 8, marginBottom: 8, display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'center' }}>
                <div>
                  <strong>{getConversationTitle(activeConversation)}</strong>
                  <p style={{ margin: '4px 0 0', color: '#9ca3af', fontSize: 12 }}>
                    {activeConversation.type === 'broadcast'
                      ? 'Creator broadcast channel'
                      : activeConversation.type === 'group'
                        ? 'Group conversation'
                        : 'Direct messaging'}
                  </p>
                </div>
                {(() => {
                  const peerId = getCounterpartyId(activeConversation);
                  const peer = peerId ? profilesById[peerId] : null;
                  return peer ? (
                    <Link to={profileHref(peer)} style={{ color: '#93c5fd', fontSize: 12 }}>
                      Open profile
                    </Link>
                  ) : null;
                })()}
              </header>

              <div
                ref={messagesScrollRef}
                onScroll={handleMessagesScroll}
                style={{ overflow: 'auto', display: 'grid', gap: isMobile ? 10 : 12, padding: isMobile ? '2px 1px 14px' : '4px 2px 10px' }}
              >
                {nextCursor ? (
                  <button type="button" onClick={() => void loadMessages(activeConversation.id, nextCursor)} style={{ justifySelf: 'center' }}>
                    Load older messages
                  </button>
                ) : null}

                {messages.map((message) => {
                  const mine = message.senderId === user.id;
                  const sender = profilesById[message.senderId] ?? null;
                  const readByOthers = (message.readBy ?? []).filter((entry) => entry.userId !== user.id);
                  const statusLabel = mine
                    ? readByOthers.length > 0
                      ? 'Read'
                      : (message.deliveredTo?.length ?? 0) > 0
                        ? 'Delivered'
                        : 'Sent'
                    : undefined;

                  return (
                    <MessageBubble
                      key={message.id}
                      message={message}
                      mine={mine}
                      sender={sender}
                      timestamp={formatRelative(message.sentAt || message.createdAt)}
                      statusLabel={statusLabel}
                      showReadReceipt={Boolean(mine && activeConversation.readReceiptsEnabled)}
                      onReact={react}
                    />
                  );
                })}
              </div>

              <div
                style={{
                  position: 'sticky',
                  bottom: 0,
                  background: '#020617',
                  borderTop: '1px solid #1f2937',
                  marginTop: 4,
                  paddingTop: 8,
                  paddingBottom: isMobile ? 6 : 2,
                  zIndex: 2,
                }}
              >
                {pendingIncomingCount > 0 ? (
                  <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 8 }}>
                    <button
                      type="button"
                      onClick={jumpToLatest}
                      style={{
                        border: '1px solid #1d4ed8',
                        background: '#1e3a8a',
                        color: '#dbeafe',
                        borderRadius: 999,
                        padding: '6px 12px',
                        fontSize: 12,
                        cursor: 'pointer',
                      }}
                    >
                      New messages ({pendingIncomingCount}) • Jump to latest
                    </button>
                  </div>
                ) : null}

                {activeTypingUsers.length > 0 ? (
                  <p style={{ margin: '0 0 8px', fontSize: 12, color: '#93c5fd' }}>
                    {activeTypingUsers.map((item) => item.displayName || item.username).join(', ')} typing…
                  </p>
                ) : null}

                <form onSubmit={(e) => void sendMessage(e)} style={{ display: 'grid', gridTemplateColumns: 'auto 1fr auto', gap: isMobile ? 6 : 8, alignItems: 'center' }}>
                  <button type="button" disabled title="Attachments (images/files) coming soon" style={{ opacity: 0.75 }}>
                    ＋
                  </button>
                  <input
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    placeholder="Write a message…"
                    maxLength={2000}
                    style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 10, color: '#e5e7eb', padding: isMobile ? '10px 10px' : '10px 12px', fontSize: isMobile ? 16 : 14 }}
                  />
                  <button type="submit" disabled={sending}>{sending ? 'Sending…' : 'Send'}</button>
                </form>
              </div>
            </>
          )}
        </section>
      </div>
    </main>
  );
}
