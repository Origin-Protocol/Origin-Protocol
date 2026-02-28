import { VideoMeta, Comment } from '../types';
import { videosApi } from '../api/client';
import { useState, FormEvent } from 'react';
import { Link } from 'react-router-dom';

interface Props {
  video: VideoMeta;
}

export default function VideoCard({ video }: Props) {
  const [liked, setLiked]             = useState(false);
  const [likeCount, setLikeCount]     = useState(video.likeCount);
  const [showComments, setShowComments] = useState(false);
  const [comments, setComments]       = useState<Comment[]>([]);
  const [loadingComments, setLoadingComments] = useState(false);
  const [commentText, setCommentText] = useState('');
  const [posting, setPosting]         = useState(false);

  async function handleLike() {
    try {
      const res = await videosApi.like(video.id);
      setLiked(res.liked);
      setLikeCount((c) => res.liked ? c + 1 : Math.max(0, c - 1));
    } catch {
      // ignore — user may not be logged in
    }
  }

  async function toggleComments() {
    if (showComments) { setShowComments(false); return; }
    setShowComments(true);
    if (comments.length > 0) return;
    setLoadingComments(true);
    try {
      const res = await videosApi.getComments(video.id);
      setComments(res.comments);
    } catch {
      // ignore
    } finally {
      setLoadingComments(false);
    }
  }

  async function handlePostComment(e: FormEvent) {
    e.preventDefault();
    const text = commentText.trim();
    if (!text) return;
    setPosting(true);
    try {
      const res = await videosApi.postComment(video.id, text);
      setComments((prev) => [res.comment, ...prev]);
      setCommentText('');
    } catch {
      // ignore — user may not be logged in
    } finally {
      setPosting(false);
    }
  }

  return (
    <article className="card" style={{ marginBottom: 'var(--sp-4)' }}>
      {/* Video player */}
      <video
        src={video.videoUrl}
        controls
        poster={video.thumbnailUrl ?? undefined}
        style={{
          width:       '100%',
          background:  '#000',
          maxHeight:   360,
          display:     'block',
        }}
      />

      {/* Content */}
      <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
        {/* Title row */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--sp-3)' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <Link
              to={`/video/${video.id}`}
              style={{ textDecoration: 'none', display: 'block' }}
            >
              <p style={{
                fontWeight:   700,
                fontSize:     15,
                color:        'var(--color-text)',
                overflow:     'hidden',
                textOverflow: 'ellipsis',
                whiteSpace:   'nowrap',
              }}>
                {video.title}
              </p>
            </Link>
            {video.description && (
              <p style={{
                fontSize:  13,
                color:     'var(--color-text-2)',
                marginTop: 'var(--sp-1)',
                lineHeight: 1.5,
                display:   '-webkit-box',
                WebkitLineClamp: 2,
                WebkitBoxOrient: 'vertical',
                overflow:  'hidden',
              }}>
                {video.description}
              </p>
            )}
          </div>

          {/* Like button */}
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
            <span style={{ fontSize: 18, lineHeight: 1 }}>{liked ? '♥' : '♡'}</span>
            <span style={{ fontSize: 12, fontWeight: 600 }}>{likeCount}</span>
          </button>
        </div>

        {/* Origin verified badge */}
        {video.originVerified && (
          <span className="badge badge--success" style={{ alignSelf: 'flex-start' }}>
            ✓ Origin verified
          </span>
        )}

        {/* Stats row */}
        <div style={{
          display:    'flex',
          gap:        'var(--sp-4)',
          fontSize:   12,
          color:      'var(--color-text-muted)',
          paddingTop: 'var(--sp-1)',
          borderTop:  '1px solid var(--color-border)',
        }}>
          <span>◉ {video.viewCount.toLocaleString()} views</span>
          <button
            onClick={() => void toggleComments()}
            className="btn btn--ghost"
            style={{
              padding:    0,
              fontSize:   12,
              color:      showComments ? 'var(--color-primary)' : 'var(--color-text-muted)',
              fontWeight: showComments ? 700 : 400,
              border:     'none',
            }}
          >
            ◎ {video.commentCount.toLocaleString()} comments
          </button>
          <span style={{ marginLeft: 'auto' }}>
            {new Date(video.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
          </span>
        </div>

        {/* Comment section */}
        {showComments && (
          <div style={{
            borderTop:   '1px solid var(--color-border)',
            paddingTop:  'var(--sp-3)',
            display:     'flex',
            flexDirection:'column',
            gap:         'var(--sp-3)',
          }}>
            {/* Post a comment */}
            <form onSubmit={(e) => void handlePostComment(e)} style={{ display: 'flex', gap: 'var(--sp-2)' }}>
              <input
                className="input"
                value={commentText}
                onChange={(e) => setCommentText(e.target.value)}
                placeholder="Add a comment…"
                style={{ flex: 1, padding: '7px 10px', fontSize: 13 }}
              />
              <button
                type="submit"
                className="btn btn--primary btn--sm"
                disabled={posting || !commentText.trim()}
              >
                {posting ? '…' : 'Post'}
              </button>
            </form>

            {/* Comments list */}
            {loadingComments ? (
              <div className="loading-row" style={{ padding: 0 }}>
                <span className="spinner" style={{ width: 14, height: 14 }} />
                <span style={{ fontSize: 13 }}>Loading comments…</span>
              </div>
            ) : comments.length === 0 ? (
              <p style={{ fontSize: 13, color: 'var(--color-text-muted)', margin: 0 }}>
                No comments yet — be the first!
              </p>
            ) : (
              comments.map((c) => (
                <div key={c.id} style={{
                  fontSize:   13,
                  color:      'var(--color-text)',
                  padding:    'var(--sp-2) var(--sp-3)',
                  background: 'var(--color-surface-2)',
                  borderRadius: 'var(--radius-sm)',
                }}>
                  <span style={{ fontWeight: 600 }}>@{c.authorId}</span>
                  {'  '}
                  <span style={{ color: 'var(--color-text-2)' }}>{c.text}</span>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </article>
  );
}
