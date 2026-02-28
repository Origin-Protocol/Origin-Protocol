import { CSSProperties, FormEvent, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { liveApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import type { LiveComment, LiveEligibility, LiveSession } from '../types';

const cardStyle: CSSProperties = {
  border: '1px solid #1f2937',
  borderRadius: 12,
  background: '#0b1220',
  padding: 12,
};

function relative(iso: string): string {
  const delta = Date.now() - Date.parse(iso);
  const mins = Math.floor(delta / 60_000);
  if (mins < 1) return 'now';
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

export default function LiveScreen() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { sessionId: routeSessionId } = useParams<{ sessionId?: string }>();
  const [eligibility, setEligibility] = useState<LiveEligibility | null>(null);
  const [sessions, setSessions] = useState<LiveSession[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [comments, setComments] = useState<LiveComment[]>([]);
  const [replyTo, setReplyTo] = useState<LiveComment | null>(null);
  const [commentText, setCommentText] = useState('');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const selectedSession = useMemo(
    () => sessions.find((item) => item.id === selectedSessionId) ?? null,
    [sessions, selectedSessionId]
  );

  async function refreshEligibility() {
    const data = await liveApi.getEligibility();
    setEligibility(data);
  }

  function goToSession(sessionId: string) {
    setSelectedSessionId(sessionId);
    navigate(`/live/${sessionId}`);
  }

  async function refreshSessions(preserveSelection = true, preferredSessionId?: string | null) {
    const data = await liveApi.listSessions('live', 80);
    setSessions(data.items);

    setSelectedSessionId((currentSelected) => {
      const fallback = data.items[0]?.id ?? null;
      if (!preserveSelection) return preferredSessionId ?? fallback;

      const candidate = preferredSessionId ?? routeSessionId ?? currentSelected;
      if (!candidate) return fallback;
      return data.items.some((item) => item.id === candidate) ? candidate : fallback;
    });
  }

  async function refreshComments(sessionId: string) {
    const data = await liveApi.listComments(sessionId);
    setComments(data.comments);
  }

  useEffect(() => {
    if (!routeSessionId) return;
    setSelectedSessionId(routeSessionId);
  }, [routeSessionId]);

  useEffect(() => {
    if (!selectedSessionId) return;
    if (routeSessionId === selectedSessionId) return;
    navigate(`/live/${selectedSessionId}`, { replace: true });
  }, [navigate, routeSessionId, selectedSessionId]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setError(null);
      try {
        await Promise.all([refreshEligibility(), refreshSessions(false, routeSessionId ?? null)]);
      } catch (err) {
        if (!cancelled) setError((err as Error).message || 'Failed to load live center.');
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [routeSessionId]);

  useEffect(() => {
    if (!selectedSessionId) {
      setComments([]);
      return;
    }

    const sessionId: string = selectedSessionId;

    let cancelled = false;
    let pollInFlight = false;
    void liveApi.joinSession(sessionId).catch(() => undefined);

    async function loadComments() {
      try {
        const data = await liveApi.listComments(sessionId);
        if (!cancelled) setComments(data.comments);
      } catch (err) {
        if (!cancelled) setError((err as Error).message || 'Failed to load live chat.');
      }
    }

    void loadComments();

    const timer = window.setInterval(() => {
      if (document.hidden || pollInFlight) return;
      pollInFlight = true;
      void (async () => {
        try {
          await Promise.all([refreshSessions(), loadComments()]);
        } finally {
          pollInFlight = false;
        }
      })();
    }, 20_000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
      void liveApi.leaveSession(sessionId).catch(() => undefined);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedSessionId]);

  async function startLive(e: FormEvent) {
    e.preventDefault();
    if (!title.trim()) {
      setError('Live title is required.');
      return;
    }

    setBusy('start');
    setError(null);
    setStatusMsg(null);
    try {
      const created = await liveApi.createSession({
        title: title.trim(),
        description: description.trim() || undefined,
      });
      setTitle('');
      setDescription('');
      setStatusMsg('You are now live.');
      await Promise.all([refreshEligibility(), refreshSessions(true, created.session.id)]);
      goToSession(created.session.id);
    } catch (err) {
      setError((err as Error).message || 'Failed to start live session.');
    } finally {
      setBusy(null);
    }
  }

  async function endLive() {
    if (!selectedSession) return;
    setBusy('end');
    setError(null);
    setStatusMsg(null);
    try {
      await liveApi.endSession(selectedSession.id);
      setStatusMsg('Live session ended.');
      setReplyTo(null);
      setCommentText('');
      await Promise.all([refreshEligibility(), refreshSessions(false)]);
      navigate('/live');
    } catch (err) {
      setError((err as Error).message || 'Failed to end live session.');
    } finally {
      setBusy(null);
    }
  }

  async function sendComment(e: FormEvent) {
    e.preventDefault();
    if (!selectedSession) return;
    const text = commentText.trim();
    if (!text) return;

    setBusy('comment');
    setError(null);
    try {
      await liveApi.postComment(selectedSession.id, {
        text,
        parentId: replyTo?.id,
      });
      setCommentText('');
      setReplyTo(null);
      await refreshComments(selectedSession.id);
      await refreshSessions();
    } catch (err) {
      setError((err as Error).message || 'Failed to send live comment.');
    } finally {
      setBusy(null);
    }
  }

  async function toggleSessionLike() {
    if (!selectedSession) return;
    setBusy('session-like');
    setError(null);
    try {
      await liveApi.toggleSessionLike(selectedSession.id);
      await refreshSessions();
    } catch (err) {
      setError((err as Error).message || 'Failed to like live session.');
    } finally {
      setBusy(null);
    }
  }

  async function toggleCommentLike(commentId: string) {
    if (!selectedSession) return;
    setBusy(`comment-like:${commentId}`);
    setError(null);
    try {
      await liveApi.toggleCommentLike(commentId);
      await refreshComments(selectedSession.id);
    } catch (err) {
      setError((err as Error).message || 'Failed to like comment.');
    } finally {
      setBusy(null);
    }
  }

  const activeMine = sessions.find((item) => item.hostUserId === user?.id && item.status === 'live') ?? null;

  return (
    <div style={{ maxWidth: 1180, margin: '0 auto', padding: '16px 12px 96px', color: '#e5e7eb' }}>
      <h2 style={{ marginTop: 0 }}>Live Center</h2>
      <p style={{ marginTop: 0, color: '#94a3b8' }}>
        Unlock live by hitting creator milestones. Admin accounts can go live instantly. Once unlocked, you can go live with real-time comments, likes, and threaded replies.
      </p>

      {error ? <p style={{ color: '#fecaca' }}>{error}</p> : null}
      {statusMsg ? <p style={{ color: '#86efac' }}>{statusMsg}</p> : null}

      <section style={{ ...cardStyle, marginBottom: 12 }}>
        <h3 style={{ marginTop: 0 }}>Go Live Access</h3>
        {eligibility ? (
          <>
            <p style={{ marginTop: 0, color: eligibility.eligible ? '#86efac' : '#fbbf24' }}>
              {eligibility.isAdminBypass
                ? '✅ Live unlocked (admin override)'
                : eligibility.eligible
                  ? '✅ Live unlocked'
                  : '🔒 Live locked until metrics are met'}
            </p>
            <div style={{ display: 'grid', gap: 6, gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
              <Metric label="Followers" value={eligibility.metrics.followers} target={eligibility.requirements.minFollowers} />
              <Metric label="Total views" value={eligibility.metrics.totalViews} target={eligibility.requirements.minTotalViews} />
              <Metric label="Published videos" value={eligibility.metrics.publishedVideos} target={eligibility.requirements.minPublishedVideos} />
              <Metric label="Verified videos" value={eligibility.metrics.verifiedVideos} target={eligibility.requirements.minVerifiedVideos} />
            </div>
          </>
        ) : (
          <p style={{ marginTop: 0, color: '#94a3b8' }}>Loading eligibility…</p>
        )}

        {eligibility?.eligible && !activeMine ? (
          <form onSubmit={startLive} style={{ marginTop: 10, display: 'grid', gap: 8 }}>
            <input
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="Live title"
              maxLength={140}
              style={inputStyle}
            />
            <textarea
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="What are you going live about?"
              maxLength={500}
              rows={3}
              style={inputStyle}
            />
            <div>
              <button type="submit" disabled={Boolean(busy)} style={buttonPrimary}>
                {busy === 'start' ? 'Starting…' : 'Go Live'}
              </button>
            </div>
          </form>
        ) : null}

        {activeMine ? (
          <div style={{ marginTop: 10, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <p style={{ margin: 0, color: '#93c5fd' }}>
              You are currently live: <strong>{activeMine.title}</strong>
            </p>
            <button type="button" style={buttonSecondary} onClick={() => goToSession(activeMine.id)}>
              Open Live Room
            </button>
          </div>
        ) : null}
      </section>

      <div style={{ display: 'grid', gap: 12, gridTemplateColumns: '320px minmax(0, 1fr)' }}>
        <section style={cardStyle}>
          <h3 style={{ marginTop: 0 }}>Live Now</h3>
          {sessions.length === 0 ? <p style={{ color: '#94a3b8' }}>No active live sessions.</p> : null}
          <div style={{ display: 'grid', gap: 8 }}>
            {sessions.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => goToSession(item.id)}
                style={{
                  textAlign: 'left',
                  border: '1px solid #1f2937',
                  borderRadius: 10,
                  background: selectedSessionId === item.id ? '#111827' : '#0f172a',
                  color: '#e5e7eb',
                  padding: 10,
                  cursor: 'pointer',
                }}
              >
                <strong>{item.title}</strong>
                <p style={{ margin: '6px 0 0', fontSize: 12, color: '#94a3b8' }}>
                  @{item.hostUsername} · {item.viewerCount} watching · {relative(item.startedAt)}
                </p>
              </button>
            ))}
          </div>
        </section>

        <section style={cardStyle}>
          {selectedSession ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
                <div>
                  <h3 style={{ margin: 0 }}>{selectedSession.title}</h3>
                  <p style={{ margin: '4px 0 0', color: '#94a3b8' }}>
                    @{selectedSession.hostUsername} · {selectedSession.viewerCount} watching · {selectedSession.likeCount} likes
                  </p>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button type="button" onClick={() => void toggleSessionLike()} disabled={Boolean(busy)} style={buttonSecondary}>
                    {selectedSession.likedByMe ? '♥ Liked' : '♡ Like'}
                  </button>
                  {selectedSession.hostUserId === user?.id ? (
                    <button type="button" onClick={() => void endLive()} disabled={Boolean(busy)} style={buttonDanger}>
                      End Live
                    </button>
                  ) : null}
                </div>
              </div>

              <div style={{ marginTop: 10, border: '1px dashed #334155', borderRadius: 10, padding: 12, color: '#93c5fd' }}>
                Live broadcast room active. Audience engagement is enabled below (comments, likes, replies).
              </div>

              <div style={{ marginTop: 12 }}>
                <h4 style={{ margin: '0 0 8px' }}>Live Chat</h4>
                <div style={{ display: 'grid', gap: 8, maxHeight: 330, overflowY: 'auto', paddingRight: 4 }}>
                  {comments.length === 0 ? <p style={{ margin: 0, color: '#94a3b8' }}>No comments yet.</p> : null}
                  {comments.map((item) => (
                    <LiveCommentItem
                      key={item.id}
                      item={item}
                      onLike={(id) => void toggleCommentLike(id)}
                      onReply={(comment) => setReplyTo(comment)}
                      busy={Boolean(busy)}
                    />
                  ))}
                </div>

                <form onSubmit={sendComment} style={{ marginTop: 10, display: 'grid', gap: 8 }}>
                  {replyTo ? (
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 12, color: '#93c5fd' }}>
                      <span>Replying to @{replyTo.authorUsername}</span>
                      <button
                        type="button"
                        onClick={() => setReplyTo(null)}
                        style={{ background: 'transparent', border: 'none', color: '#93c5fd', cursor: 'pointer' }}
                      >
                        Cancel
                      </button>
                    </div>
                  ) : null}
                  <textarea
                    value={commentText}
                    onChange={(event) => setCommentText(event.target.value)}
                    placeholder="Say something in live chat…"
                    rows={3}
                    maxLength={500}
                    style={inputStyle}
                  />
                  <div>
                    <button type="submit" disabled={Boolean(busy) || !commentText.trim()} style={buttonPrimary}>
                      Send
                    </button>
                  </div>
                </form>
              </div>
            </>
          ) : (
            <p style={{ margin: 0, color: '#94a3b8' }}>Select a live session to join chat.</p>
          )}
        </section>
      </div>
    </div>
  );
}

function Metric({ label, value, target }: { label: string; value: number; target: number }) {
  const met = value >= target;
  return (
    <div style={{ border: '1px solid #1f2937', borderRadius: 8, padding: 8 }}>
      <strong>{label}</strong>
      <p style={{ margin: '4px 0 0', color: met ? '#86efac' : '#fbbf24' }}>
        {value.toLocaleString()} / {target.toLocaleString()}
      </p>
    </div>
  );
}

function LiveCommentItem(props: {
  item: LiveComment;
  onLike: (id: string) => void;
  onReply: (item: LiveComment) => void;
  busy: boolean;
  depth?: number;
}) {
  const depth = props.depth ?? 0;
  return (
    <div style={{ border: '1px solid #1f2937', borderRadius: 8, padding: 8, marginLeft: depth * 18 }}>
      <p style={{ margin: 0, fontSize: 12, color: '#93c5fd' }}>
        @{props.item.authorUsername} · {relative(props.item.createdAt)}
      </p>
      <p style={{ margin: '4px 0 6px' }}>{props.item.text}</p>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <button type="button" disabled={props.busy} onClick={() => props.onLike(props.item.id)} style={miniButton}>
          {props.item.likedByMe ? '♥' : '♡'} {props.item.likeCount}
        </button>
        {depth < 1 ? (
          <button type="button" disabled={props.busy} onClick={() => props.onReply(props.item)} style={miniButton}>
            Reply
          </button>
        ) : null}
      </div>

      {props.item.replies.length > 0 ? (
        <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
          {props.item.replies.map((reply) => (
            <LiveCommentItem
              key={reply.id}
              item={reply}
              depth={depth + 1}
              onLike={props.onLike}
              onReply={props.onReply}
              busy={props.busy}
            />
          ))}
        </div>
      ) : null}
    </div>
  );
}

const inputStyle: CSSProperties = {
  width: '100%',
  border: '1px solid #334155',
  borderRadius: 8,
  background: '#0f172a',
  color: '#e5e7eb',
  padding: '8px 10px',
};

const buttonPrimary: CSSProperties = {
  border: '1px solid #7c3aed',
  background: '#7c3aed',
  color: '#fff',
  borderRadius: 8,
  padding: '8px 12px',
  cursor: 'pointer',
};

const buttonSecondary: CSSProperties = {
  border: '1px solid #334155',
  background: '#0f172a',
  color: '#cbd5e1',
  borderRadius: 8,
  padding: '8px 12px',
  cursor: 'pointer',
};

const buttonDanger: CSSProperties = {
  border: '1px solid #7f1d1d',
  background: '#450a0a',
  color: '#fecaca',
  borderRadius: 8,
  padding: '8px 12px',
  cursor: 'pointer',
};

const miniButton: CSSProperties = {
  border: '1px solid #334155',
  background: 'transparent',
  color: '#cbd5e1',
  borderRadius: 6,
  padding: '3px 8px',
  cursor: 'pointer',
  fontSize: 12,
};
