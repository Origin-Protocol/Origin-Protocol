import { FormEvent, useEffect, useMemo, useState } from 'react';
import {
  abigailApi,
  getAbigailErrorStatusCode,
  getOrCreateAbigailSessionId,
  hasAbigailApiKeyConfigured,
  setAbigailApiKeyRuntime,
  socialApi,
} from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { Link } from 'react-router-dom';
import {
  AbigailChatMessage,
  AbigailMemoryEvent,
  AbigailProfileSettings,
  AbigailRecommendation,
  SocialSignal,
} from '../types';
import {
  getNotificationPermission,
  notifyWithExternalOpen,
  requestBrowserNotificationPermission,
  supportsBrowserNotifications,
} from '../utils/browserNotifications';

const CHAT_HISTORY_KEY_PREFIX = 'origin_abigail_chat_history_v1_';
const ABIGAIL_NOTIFIED_RECS_KEY = 'origin_abigail_notified_recs_v1';

function automatedProfileSettings(): AbigailProfileSettings {
  return {
    tone: 'friendly, concise, supportive',
    boundaries: 'no harmful content, no private data assumptions',
    goals: 'improve learning, focus, and creator productivity',
  };
}

function chatStorageKey(userId: string): string {
  return `${CHAT_HISTORY_KEY_PREFIX}${userId}`;
}

function readChatHistory(userId: string): AbigailChatMessage[] {
  try {
    const raw = window.localStorage.getItem(chatStorageKey(userId));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as AbigailChatMessage[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeChatHistory(userId: string, history: AbigailChatMessage[]) {
  window.localStorage.setItem(chatStorageKey(userId), JSON.stringify(history.slice(-80)));
}

function recommendationHref(item: { href?: string }): string {
  if (!item.href || !item.href.trim()) return '/feed';
  return item.href;
}

function recommendationIsExternal(item: { href?: string }): boolean {
  return Boolean(item.href && /^https?:\/\//i.test(item.href));
}

export default function AbigailScreen() {
  const { user } = useAuth();
  const [sessionId, setSessionId] = useState<string>('');
  const [chatHistory, setChatHistory] = useState<AbigailChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatBusy, setChatBusy] = useState(false);
  const [chatOffline, setChatOffline] = useState(false);

  const [memoryEvents, setMemoryEvents] = useState<AbigailMemoryEvent[]>([]);
  const [memoryOffline, setMemoryOffline] = useState(false);
  const [memoryBusy, setMemoryBusy] = useState(false);

  const [recommendations, setRecommendations] = useState<AbigailRecommendation[]>([]);
  const [recommendationsOffline, setRecommendationsOffline] = useState(false);
  const [notificationPermission, setNotificationPermission] = useState<NotificationPermission>(() => getNotificationPermission());

  const [socialSignals, setSocialSignals] = useState<SocialSignal[]>([]);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [apiStatusCode, setApiStatusCode] = useState<number | null>(null);
  const [apiLastError, setApiLastError] = useState<string | null>(null);
  const [apiLastOperation, setApiLastOperation] = useState<string | null>(null);
  const [diagnosticsCopyState, setDiagnosticsCopyState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const [abigailApiKeyInput, setAbigailApiKeyInput] = useState('');
  const [hasApiKey, setHasApiKey] = useState(() => hasAbigailApiKeyConfigured());
  const profileSettings = useMemo(() => automatedProfileSettings(), []);

  function markApiSuccess(operation: string, statusCode: number | null | undefined) {
    setApiLastOperation(operation);
    setApiStatusCode(statusCode ?? null);
    setApiLastError(null);
  }

  function markApiFailure(operation: string, error: unknown) {
    const message = (error as Error)?.message || 'Abigail request failed.';
    setApiLastOperation(operation);
    setApiStatusCode(getAbigailErrorStatusCode(error));
    setApiLastError(message);
  }

  async function copyDiagnostics() {
    if (!user) return;

    const payload = {
      operation: apiLastOperation,
      statusCode: apiStatusCode,
      lastError: apiLastError,
      userId: user.id,
      sessionId: sessionId || null,
      chatOffline,
      memoryOffline,
      recommendationsOffline,
      capturedAt: new Date().toISOString(),
    };

    try {
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      setDiagnosticsCopyState('copied');
    } catch {
      setDiagnosticsCopyState('failed');
    }

    window.setTimeout(() => {
      setDiagnosticsCopyState('idle');
    }, 1800);
  }

  useEffect(() => {
    if (!user?.id) return;
    const userId = user.id;
    const sid = getOrCreateAbigailSessionId(userId);
    setSessionId(sid);
    setChatHistory(readChatHistory(userId));
    setHasApiKey(hasAbigailApiKeyConfigured());

    let cancelled = false;
    async function hydrate() {
      setStatusMsg(null);
      try {
        const [memory, recs] = await Promise.all([
          abigailApi.memorySnapshot({ userId, sessionId: sid }),
          abigailApi.recommendations({ userId, sessionId: sid }),
        ]);
        if (cancelled) return;
        setMemoryEvents(memory.events);
        setMemoryOffline(memory.offline);
        setRecommendations(recs.items);
        setRecommendationsOffline(recs.offline);
        markApiSuccess('hydrate', recs.statusCode ?? memory.statusCode);
        maybeNotifyRecommendation(recs.items);
      } catch (err) {
        if (!cancelled) {
          markApiFailure('hydrate', err);
          setStatusMsg((err as Error).message || 'Unable to load Abigail context right now.');
        }
      }
    }

    void hydrate();
    return () => {
      cancelled = true;
    };
  }, [user?.id]);

  async function refreshSocialSignals(): Promise<SocialSignal[]> {
    try {
      const [yt, tt, x] = await Promise.all([socialApi.youtube(), socialApi.tiktok(), socialApi.x()]);
      const items = [...yt.items, ...tt.items, ...x.items].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      setSocialSignals(items);
      return items;
    } catch {
      setSocialSignals([]);
      return [];
    }
  }

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

  function maybeNotifyRecommendation(items: AbigailRecommendation[]) {
    if (!supportsBrowserNotifications() || Notification.permission !== 'granted') return;
    const seen = loadNotifiedRecommendationIds();
    const next = items.find((item) => !seen.has(item.id));
    if (!next) return;
    const href = recommendationHref(next);
    const shown = notifyWithExternalOpen({
      title: 'Abigail recommendation',
      body: `${next.title} (${next.kind})`,
      href,
      tag: `abigail-rec-${next.id}`,
    });
    if (shown) {
      seen.add(next.id);
      saveNotifiedRecommendationIds(seen);
    }
  }

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

  async function sendChat(event: FormEvent) {
    event.preventDefault();
    if (!user || !chatInput.trim() || chatBusy) return;

    const text = chatInput.trim();
    const userMessage: AbigailChatMessage = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: text,
      createdAt: new Date().toISOString(),
    };

    const nextHistory = [...chatHistory, userMessage];
    setChatHistory(nextHistory);
    writeChatHistory(user.id, nextHistory);
    setChatInput('');
    setChatBusy(true);
    setStatusMsg(null);

    try {
      const response = await abigailApi.chat({
        userId: user.id,
        sessionId,
        message: text,
        history: nextHistory,
        profileSettings,
      });

      setChatOffline(response.offline);
      markApiSuccess('chat', response.statusCode);
      const assistantMessage: AbigailChatMessage = {
        id: `a-${Date.now()}`,
        role: 'assistant',
        content: response.reply,
        createdAt: new Date().toISOString(),
      };
      const merged = [...nextHistory, assistantMessage];
      setChatHistory(merged);
      writeChatHistory(user.id, merged);
      setSessionId(response.sessionId);
    } catch (err) {
      setChatOffline(false);
      markApiFailure('chat', err);
      setStatusMsg((err as Error).message || 'Failed to send message to Abigail.');
    } finally {
      setChatBusy(false);
    }
  }

  async function syncSocialSignals() {
    if (!user) return;
    const signals = socialSignals.length > 0 ? socialSignals : await refreshSocialSignals();
    if (signals.length === 0) {
      setStatusMsg('No social signals available to sync right now.');
      return;
    }
    setMemoryBusy(true);
    const events: AbigailMemoryEvent[] = signals.slice(0, 20).map((signal) => ({
      id: `social-${signal.id}`,
      type: signal.type,
      title: `${signal.platform.toUpperCase()} ${signal.type}`,
      detail: signal.title,
      createdAt: signal.createdAt,
    }));

    try {
      const result = await abigailApi.updateMemory({
        userId: user.id,
        sessionId,
        events,
        profileSettings,
      });
      setMemoryOffline(result.offline);
      markApiSuccess('memory/update', result.statusCode);
      setMemoryEvents((prev) => [...events, ...prev].slice(0, 80));
      if (result.offline) {
        setStatusMsg('Social signals captured locally (Abigail offline).');
      } else if (result.skipped > 0) {
        setStatusMsg(`Social signals synced (${result.ingested} ingested, ${result.skipped} skipped by backend filters).`);
      } else {
        setStatusMsg('Social signals synced to Abigail memory.');
      }
    } catch (err) {
      setMemoryOffline(false);
      markApiFailure('memory/update', err);
      setStatusMsg((err as Error).message || 'Failed to update Abigail memory.');
    } finally {
      setMemoryBusy(false);
    }
  }

  async function refreshRecommendations() {
    if (!user) return;
    try {
      const recs = await abigailApi.recommendations({ userId: user.id, sessionId });
      setRecommendations(recs.items);
      setRecommendationsOffline(recs.offline);
      markApiSuccess('recommendations', recs.statusCode);
      maybeNotifyRecommendation(recs.items);
    } catch (err) {
      setRecommendationsOffline(false);
      markApiFailure('recommendations', err);
      setStatusMsg((err as Error).message || 'Failed to refresh recommendations.');
    }
  }

  const memoryLane = useMemo(() => {
    return [...memoryEvents].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 40);
  }, [memoryEvents]);

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

  if (!user) {
    return <main style={{ maxWidth: 980, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>Sign in to use Abigail.</main>;
  }

  return (
    <main style={{ maxWidth: 1120, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>
      <h2 style={{ marginBottom: 6 }}>Abigail</h2>
      <p style={{ marginTop: 0, color: '#9ca3af' }}>
        Origin routes your session and identity. Abigail handles reasoning, memory, and personalization.
      </p>
      {statusMsg ? <p style={{ color: '#93c5fd', fontSize: 13 }}>{statusMsg}</p> : null}

      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10, marginBottom: 12 }}>
        <strong>Session</strong>
        <p style={{ margin: '4px 0 0', color: '#9ca3af', fontSize: 12 }}>
          userId: {user.id} • sessionId: {sessionId || 'initializing'}
        </p>
      </section>

      {!hasApiKey ? (
        <section style={{ border: '1px solid #7f1d1d', borderRadius: 12, background: '#111827', padding: 10, marginBottom: 12 }}>
          <strong>Abigail API key required</strong>
          <p style={{ margin: '4px 0 8px', color: '#fca5a5', fontSize: 12 }}>
            Chat/memory write routes need an API key. Paste it once here for this browser session.
          </p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <input
              value={abigailApiKeyInput}
              onChange={(event) => setAbigailApiKeyInput(event.target.value)}
              placeholder="Paste Abigail API key"
              style={{ minWidth: 320, flex: '1 1 320px', border: '1px solid #334155', borderRadius: 8, background: '#020617', color: '#fff', padding: '8px 10px' }}
            />
            <button
              type="button"
              onClick={() => {
                setAbigailApiKeyRuntime(abigailApiKeyInput);
                setHasApiKey(hasAbigailApiKeyConfigured());
                setStatusMsg('Abigail API key saved in browser storage.');
              }}
              disabled={!abigailApiKeyInput.trim()}
            >
              Save key
            </button>
          </div>
        </section>
      ) : null}

      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10, marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
          <strong>API diagnostics</strong>
          <button type="button" onClick={() => void copyDiagnostics()} style={{ fontSize: 12 }}>
            {diagnosticsCopyState === 'copied' ? 'Copied' : diagnosticsCopyState === 'failed' ? 'Copy failed' : 'Copy diagnostics'}
          </button>
        </div>
        <p style={{ margin: '4px 0 0', color: '#9ca3af', fontSize: 12 }}>
          last operation: {apiLastOperation ?? '—'} • status code: {apiStatusCode ?? 'n/a'}
        </p>
        <p style={{ margin: '4px 0 0', color: apiLastError ? '#fca5a5' : '#86efac', fontSize: 12 }}>
          last error: {apiLastError ?? 'none'}
        </p>
      </section>

      <section style={{ display: 'grid', gap: 12, gridTemplateColumns: 'minmax(0, 1fr) 360px' }}>
        <div style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10 }}>
          <h3 style={{ marginTop: 0 }}>Chat</h3>
          {chatOffline ? <p style={{ marginTop: 0, color: '#fbbf24', fontSize: 12 }}>Abigail appears offline. Responses are in fallback mode.</p> : null}
          <div style={{ display: 'grid', gap: 8, maxHeight: 420, overflowY: 'auto', marginBottom: 10 }}>
            {chatHistory.length === 0 ? <p style={{ margin: 0, color: '#9ca3af' }}>Start a conversation with Abigail.</p> : null}
            {chatHistory.map((item) => (
              <article
                key={item.id}
                style={{
                  border: '1px solid #1f2937',
                  borderRadius: 10,
                  padding: 8,
                  background: item.role === 'assistant' ? '#111827' : '#0f172a',
                  justifySelf: item.role === 'assistant' ? 'stretch' : 'stretch',
                }}
              >
                <p style={{ margin: 0, fontSize: 12, color: '#93c5fd' }}>{item.role === 'assistant' ? 'Abigail' : 'You'}</p>
                <p style={{ margin: '4px 0 0' }}>{item.content}</p>
              </article>
            ))}
          </div>

          <form onSubmit={(event) => void sendChat(event)} style={{ display: 'grid', gap: 8 }}>
            <textarea
              value={chatInput}
              onChange={(event) => setChatInput(event.target.value)}
              rows={3}
              maxLength={1500}
              placeholder="Ask Abigail anything about your goals, focus, and content habits…"
              style={{ width: '100%', border: '1px solid #334155', borderRadius: 8, background: '#020617', color: '#fff', padding: '8px 10px' }}
            />
            <button type="submit" disabled={chatBusy || !chatInput.trim()} style={{ width: 160 }}>
              {chatBusy ? 'Sending…' : 'Send to Abigail'}
            </button>
          </form>
        </div>

        <div style={{ display: 'grid', gap: 12, alignContent: 'start' }}>
          <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center' }}>
              <h3 style={{ margin: 0 }}>Recommendations</h3>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ color: notificationStateColor, fontSize: 12 }}>{notificationStateLabel}</span>
                {supportsBrowserNotifications() && notificationPermission !== 'granted' ? (
                  <button type="button" onClick={() => void enableAbigailAlerts()}>Enable alerts</button>
                ) : null}
                {supportsBrowserNotifications() && notificationPermission === 'granted' ? (
                  <button type="button" onClick={() => sendTestAbigailNotification()}>Test notification</button>
                ) : null}
                <button type="button" onClick={() => void refreshRecommendations()}>Refresh</button>
              </div>
            </div>
            {recommendationsOffline ? <p style={{ color: '#fbbf24', fontSize: 12 }}>Using fallback recommendations.</p> : null}
            <div style={{ display: 'grid', gap: 8 }}>
              {recommendations.map((item) => {
                const href = recommendationHref(item);
                const external = recommendationIsExternal(item);
                const commonStyle = {
                  border: '1px solid #1f2937',
                  borderRadius: 8,
                  padding: 8,
                  background: '#0f172a',
                  textDecoration: 'none',
                  color: '#e5e7eb',
                  display: 'block',
                } as const;

                if (external) {
                  return (
                    <a key={item.id} href={href} target="_blank" rel="noreferrer" style={commonStyle}>
                      <p style={{ margin: 0 }}><strong>{item.title}</strong> <span style={{ color: '#9ca3af' }}>({item.kind})</span></p>
                      <p style={{ margin: '4px 0 0', color: '#93c5fd', fontSize: 12 }}>{item.reason}</p>
                    </a>
                  );
                }

                return (
                  <Link key={item.id} to={href} style={commonStyle}>
                    <p style={{ margin: 0 }}><strong>{item.title}</strong> <span style={{ color: '#9ca3af' }}>({item.kind})</span></p>
                    <p style={{ margin: '4px 0 0', color: '#93c5fd', fontSize: 12 }}>{item.reason}</p>
                  </Link>
                );
              })}
              {recommendations.length === 0 ? <p style={{ margin: 0, color: '#9ca3af' }}>No recommendations yet.</p> : null}
            </div>
          </section>
        </div>
      </section>

      <section style={{ marginTop: 12, display: 'grid', gap: 12, gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)' }}>
        <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center' }}>
            <h3 style={{ margin: 0 }}>Memory Lane</h3>
            <button type="button" onClick={() => void syncSocialSignals()} disabled={memoryBusy}>
              {memoryBusy ? 'Syncing…' : 'Sync social signals'}
            </button>
          </div>
          {memoryOffline ? <p style={{ color: '#fbbf24', fontSize: 12 }}>Memory sync is currently offline.</p> : null}
          <div style={{ display: 'grid', gap: 8, maxHeight: 280, overflowY: 'auto' }}>
            {memoryLane.map((item) => (
              <article key={item.id} style={{ border: '1px solid #1f2937', borderRadius: 8, padding: 8, background: '#0f172a' }}>
                <p style={{ margin: 0 }}><strong>{item.title}</strong></p>
                {item.detail ? <p style={{ margin: '4px 0 0', color: '#cbd5e1', fontSize: 13 }}>{item.detail}</p> : null}
                <p style={{ margin: '4px 0 0', color: '#9ca3af', fontSize: 11 }}>{new Date(item.createdAt).toLocaleString()}</p>
              </article>
            ))}
            {memoryLane.length === 0 ? <p style={{ margin: 0, color: '#9ca3af' }}>No memory events available yet.</p> : null}
          </div>
        </section>

        <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 10 }}>
          <h3 style={{ marginTop: 0 }}>Social integration placeholders</h3>
          <p style={{ marginTop: 0, color: '#9ca3af', fontSize: 12 }}>
            Mock results returned via /api/social/youtube, /api/social/tiktok, and /api/social/x (fallback enabled).
          </p>
          <div style={{ display: 'grid', gap: 8, maxHeight: 280, overflowY: 'auto' }}>
            {socialSignals.map((signal) => (
              <article key={signal.id} style={{ border: '1px solid #1f2937', borderRadius: 8, padding: 8, background: '#0f172a' }}>
                <p style={{ margin: 0 }}>
                  <strong>{signal.platform.toUpperCase()}</strong> • {signal.type}
                </p>
                <p style={{ margin: '4px 0 0', color: '#cbd5e1', fontSize: 13 }}>{signal.title}</p>
                <p style={{ margin: '4px 0 0', color: '#9ca3af', fontSize: 11 }}>{new Date(signal.createdAt).toLocaleString()}</p>
              </article>
            ))}
            {socialSignals.length === 0 ? <p style={{ margin: 0, color: '#9ca3af' }}>No social signals loaded.</p> : null}
          </div>
        </section>
      </section>
    </main>
  );
}
