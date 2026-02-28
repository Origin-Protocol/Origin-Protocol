import { useEffect, useState, FormEvent } from 'react';
import { useParams, Link } from 'react-router-dom';
import { videosApi } from '../api/client';
import { VideoMeta, Comment } from '../types';

export default function VideoDetailScreen() {
  const { id } = useParams<{ id: string }>();

  const [video, setVideo]           = useState<VideoMeta | null>(null);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState<string | null>(null);
  const [liked, setLiked]           = useState(false);
  const [likeCount, setLikeCount]   = useState(0);
  const [comments, setComments]     = useState<Comment[]>([]);
  const [commentText, setCommentText] = useState('');
  const [posting, setPosting]       = useState(false);

  useEffect(() => {
    if (!id) return;
    void (async () => {
      try {
        const [{ video: v }, { comments: c }] = await Promise.all([
          videosApi.get(id),
          videosApi.getComments(id),
        ]);
        setVideo(v);
        setLikeCount(v.likeCount);
        setComments(c);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    })();
  }, [id]);

  async function handleLike() {
    if (!id) return;
    try {
      const res = await videosApi.like(id);
      setLiked(res.liked);
      setLikeCount((c) => res.liked ? c + 1 : Math.max(0, c - 1));
    } catch {
      // not logged in
    }
  }

  async function handleComment(e: FormEvent) {
    e.preventDefault();
    const text = commentText.trim();
    if (!text || !id) return;
    setPosting(true);
    try {
      const res = await videosApi.postComment(id, text);
      setComments((prev) => [res.comment, ...prev]);
      setCommentText('');
    } catch {
      // not logged in
    } finally {
      setPosting(false);
    }
  }

  const backLink = (
    <Link
      to="/"
      style={{
        display:        'inline-flex',
        alignItems:     'center',
        gap:            4,
        fontSize:       13,
        color:          'var(--color-text-muted)',
        textDecoration: 'none',
        marginTop:      'var(--sp-4)',
        marginBottom:   'var(--sp-4)',
      }}
    >
      ← Back to feed
    </Link>
  );

  if (loading) {
    return (
      <main className="page">
        {backLink}
        <div className="skeleton" style={{ height: 280, borderRadius: 'var(--radius-lg)', marginBottom: 'var(--sp-3)' }} />
        <div className="skeleton" style={{ height: 22, width: '60%', marginBottom: 'var(--sp-2)' }} />
        <div className="skeleton" style={{ height: 14, width: '40%' }} />
      </main>
    );
  }

  if (error || !video) {
    return (
      <main className="page">
        {backLink}
        <div className="inline-error">⚠ {error ?? 'Video not found.'}</div>
      </main>
    );
  }

  return (
    <main className="page" style={{ paddingBottom: 100 }}>
      {backLink}

      {/* Video player */}
      <div className="card" style={{ marginBottom: 'var(--sp-4)' }}>
        <video
          src={video.videoUrl}
          controls
          poster={video.thumbnailUrl ?? undefined}
          style={{ width: '100%', background: '#000', display: 'block', maxHeight: 380 }}
        />
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
          {/* Title + like */}
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--sp-3)' }}>
            <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--color-text)', flex: 1, lineHeight: 1.4 }}>
              {video.title}
            </h1>
            <button
              onClick={() => void handleLike()}
              className="btn btn--ghost btn--sm"
              style={{
                flexShrink:    0,
                flexDirection: 'column',
                gap:           2,
                padding:       '6px 10px',
                borderRadius:  'var(--radius-md)',
                background:    liked ? 'var(--color-error-s)' : undefined,
                color:         liked ? 'var(--color-error)' : 'var(--color-text-muted)',
              }}
              aria-label={liked ? 'Unlike' : 'Like'}
            >
              <span style={{ fontSize: 20, lineHeight: 1 }}>{liked ? '♥' : '♡'}</span>
              <span style={{ fontSize: 12, fontWeight: 600 }}>{likeCount.toLocaleString()}</span>
            </button>
          </div>

          {/* Origin badge */}
          {video.originVerified && (
            <span className="badge badge--success" style={{ alignSelf: 'flex-start' }}>
              ✓ Origin verified
            </span>
          )}

          {/* Description */}
          {video.description && (
            <p style={{ fontSize: 14, color: 'var(--color-text-2)', lineHeight: 1.7 }}>
              {video.description}
            </p>
          )}

          {/* Meta row */}
          <div style={{
            display:    'flex',
            gap:        'var(--sp-4)',
            fontSize:   12,
            color:      'var(--color-text-muted)',
            paddingTop: 'var(--sp-2)',
            borderTop:  '1px solid var(--color-border)',
          }}>
            <span>◉ {video.viewCount.toLocaleString()} views</span>
            <span>◎ {video.commentCount.toLocaleString()} comments</span>
            <span style={{ marginLeft: 'auto' }}>
              {new Date(video.createdAt).toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' })}
            </span>
          </div>
        </div>
      </div>

      {/* Comments */}
      <h2 className="section-title">Comments</h2>

      <form
        onSubmit={(e) => void handleComment(e)}
        style={{ display: 'flex', gap: 'var(--sp-2)', marginBottom: 'var(--sp-5)' }}
      >
        <input
          className="input"
          value={commentText}
          onChange={(e) => setCommentText(e.target.value)}
          placeholder="Add a comment…"
          style={{ flex: 1 }}
        />
        <button
          type="submit"
          className="btn btn--primary btn--sm"
          disabled={posting || !commentText.trim()}
        >
          {posting ? '…' : 'Post'}
        </button>
      </form>

      {comments.length === 0 ? (
        <div className="empty-state" style={{ padding: 'var(--sp-8) 0' }}>
          <span className="empty-state-icon">💬</span>
          <p>No comments yet — be the first!</p>
        </div>
      ) : (
        comments.map((c) => (
          <div key={c.id} className="card" style={{ marginBottom: 'var(--sp-3)' }}>
            <div className="card-body" style={{ padding: 'var(--sp-3) var(--sp-4)' }}>
              <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--color-text)' }}>
                @{c.authorId}
              </span>
              <p style={{ fontSize: 14, color: 'var(--color-text-2)', marginTop: 3, lineHeight: 1.6 }}>
                {c.text}
              </p>
              <p style={{ fontSize: 11, color: 'var(--color-text-muted)', marginTop: 4 }}>
                {new Date(c.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
              </p>
            </div>
          </div>
        ))
      )}
    </main>
  );
}
