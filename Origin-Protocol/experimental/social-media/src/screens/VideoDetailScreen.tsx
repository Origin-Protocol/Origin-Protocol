import { FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { resolveApiAssetUrl, videosApi } from '../api/client';
import { Comment, VideoMeta } from '../types';
import { parseProtectionMeta } from '../utils/provenance';

export default function VideoDetailScreen() {
  const { id } = useParams();
  const [searchParams] = useSearchParams();
  const [video, setVideo] = useState<VideoMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [liked, setLiked] = useState(false);
  const [likeBusy, setLikeBusy] = useState(false);
  const [comments, setComments] = useState<Comment[]>([]);
  const [commentsBusy, setCommentsBusy] = useState(true);
  const [commentDraft, setCommentDraft] = useState('');
  const [commentBusy, setCommentBusy] = useState(false);
  const commentsPanelRef = useRef<HTMLDivElement | null>(null);
  const commentInputRef = useRef<HTMLTextAreaElement | null>(null);
  const likeInFlightRef = useRef(false);

  const isDesktop = typeof window !== 'undefined' ? window.innerWidth >= 980 : true;
  const focusComments = searchParams.get('comments') === '1' || searchParams.get('comments') === 'true';

  useEffect(() => {
    let cancelled = false;

    async function load() {
      if (!id) {
        setError('Video id is missing.');
        setLoading(false);
        return;
      }

      setLoading(true);
      setError(null);
      try {
        const [videoRes, commentsRes] = await Promise.all([
          videosApi.get(id),
          videosApi.getComments(id),
        ]);
        if (cancelled) return;
        setVideo(videoRes.video);
        setComments(commentsRes.comments);
      } catch (err) {
        if (cancelled) return;
        setError((err as Error).message || 'Failed to load video.');
      } finally {
        if (!cancelled) {
          setLoading(false);
          setCommentsBusy(false);
        }
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [id]);

  const uploader = useMemo(() => {
    if (!video) return 'creator';
    return video.creatorDisplayName || video.creatorUsername || 'Unknown creator';
  }, [video]);

  const cleanDescription = useMemo(() => {
    if (!video) return '';
    return parseProtectionMeta(video.description).cleanDescription;
  }, [video]);

  const verificationStatus = useMemo(() => {
    if (!video) return 'Pending verification';
    if (video.originVerified) return 'Verified';
    const reason = video.originReasons?.[0]?.message;
    return reason ? `Failed: ${reason}` : 'Pending verification';
  }, [video]);

  useEffect(() => {
    if (!focusComments || loading) return;
    const timer = window.setTimeout(() => {
      commentsPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      commentInputRef.current?.focus();
    }, 40);
    return () => {
      window.clearTimeout(timer);
    };
  }, [focusComments, loading]);

  async function handleLike() {
    if (!video || likeBusy || likeInFlightRef.current) return;
    likeInFlightRef.current = true;
    setLikeBusy(true);
    try {
      const res = await videosApi.like(video.id);
      setLiked(res.liked);
      setVideo((prev) => (prev ? { ...prev, likeCount: res.likeCount } : prev));
    } finally {
      setLikeBusy(false);
      likeInFlightRef.current = false;
    }
  }

  async function handleSubmitComment(event: FormEvent) {
    event.preventDefault();
    if (!video || commentBusy) return;
    const text = commentDraft.trim();
    if (!text) return;

    setCommentBusy(true);
    try {
      const res = await videosApi.postComment(video.id, text);
      setComments((prev) => [...prev, res.comment]);
      setCommentDraft('');
      setVideo((prev) => (prev ? { ...prev, commentCount: prev.commentCount + 1 } : prev));
    } finally {
      setCommentBusy(false);
    }
  }

  if (loading) {
    return <main style={{ maxWidth: 1180, margin: '16px auto', color: '#cbd5e1', padding: 12 }}>Loading video…</main>;
  }

  if (error || !video) {
    return (
      <main style={{ maxWidth: 1180, margin: '16px auto', color: '#fff', padding: 12 }}>
        <p style={{ color: '#fca5a5' }}>Error: {error ?? 'Video not found.'}</p>
        <Link to="/feed" style={{ color: '#93c5fd' }}>Back to feed</Link>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 1180, margin: '10px auto', color: '#fff', padding: 12 }}>
      <p style={{ margin: '0 0 8px' }}>
        <Link to="/feed" style={{ color: '#93c5fd' }}>← Back to feed</Link>
      </p>

      <section
        style={{
          display: 'grid',
          gridTemplateColumns: isDesktop ? 'minmax(0, 1fr) minmax(360px, 420px)' : '1fr',
          gap: 12,
          alignItems: 'start',
        }}
      >
        <article style={{ border: '1px solid #1f2937', borderRadius: 14, overflow: 'hidden', background: '#000' }}>
          <video
            src={resolveApiAssetUrl(video.videoUrl)}
            controls
            autoPlay
            playsInline
            poster={resolveApiAssetUrl(video.thumbnailUrl) || undefined}
            style={{ width: '100%', maxHeight: '72vh', objectFit: 'contain', background: '#000' }}
          />

          <div style={{ padding: 12, background: '#0b1220' }}>
            <h2 style={{ margin: 0 }}>{video.title}</h2>
            <p style={{ margin: '5px 0 0', color: '#93c5fd' }}>by {uploader}</p>
            {cleanDescription ? <p style={{ margin: '8px 0', color: '#d1d5db' }}>{cleanDescription}</p> : null}

            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
              {video.originBundleId ? (
                <span style={{ fontSize: 12, color: '#67e8f9' }}>🛡 Origin Protected</span>
              ) : null}
              <span style={{ fontSize: 12, color: video.originVerified ? '#86efac' : (video.originReasons?.length ? '#fca5a5' : '#fcd34d') }}>
                {video.originVerified ? '✅ Verified' : (video.originReasons?.length ? '❌ Failed verification' : '⏳ Pending verification')}
              </span>
              {(video.originBundleId || video.originVerified || (video.originReasons?.length ?? 0) > 0) ? (
                <Link to={`/verify/${video.id}`} style={{ fontSize: 12, color: '#93c5fd' }}>View proof</Link>
              ) : null}
              <span style={{ fontSize: 12, color: '#9ca3af' }}>{verificationStatus}</span>
            </div>

            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => void handleLike()}
                disabled={likeBusy}
                style={{
                  borderRadius: 999,
                  border: '1px solid #374151',
                  background: '#111827',
                  color: '#fff',
                  padding: '7px 12px',
                  cursor: likeBusy ? 'default' : 'pointer',
                }}
              >
                {liked ? '❤️' : '🤍'} {video.likeCount}
              </button>
              <span style={{ alignSelf: 'center', color: '#9ca3af', fontSize: 13 }}>
                💬 {video.commentCount} • 👁 {video.viewCount}
              </span>
            </div>
          </div>
        </article>

        <aside ref={commentsPanelRef} style={{ border: '1px solid #1f2937', borderRadius: 14, background: '#0b1220', overflow: 'hidden' }}>
          <div style={{ borderBottom: '1px solid #1f2937', padding: 10 }}>
            <h3 style={{ margin: 0 }}>Comments</h3>
          </div>

          <div style={{ maxHeight: isDesktop ? '60vh' : '40vh', overflowY: 'auto', padding: 10 }}>
            {commentsBusy ? (
              <p style={{ margin: 0, color: '#9ca3af' }}>Loading comments…</p>
            ) : comments.length === 0 ? (
              <p style={{ margin: 0, color: '#9ca3af' }}>No comments yet.</p>
            ) : (
              comments.map((comment) => (
                <p key={comment.id} style={{ margin: '0 0 10px', color: '#e5e7eb', fontSize: 13 }}>
                  <strong>{comment.authorDisplayName || comment.authorUsername || comment.authorId.slice(0, 8)}</strong> {comment.text}
                </p>
              ))
            )}
          </div>

          <form onSubmit={(event) => void handleSubmitComment(event)} style={{ borderTop: '1px solid #1f2937', padding: 10, display: 'grid', gap: 8 }}>
            <textarea
              ref={commentInputRef}
              rows={3}
              value={commentDraft}
              onChange={(event) => setCommentDraft(event.target.value)}
              placeholder="Write a comment"
              maxLength={500}
              style={{ width: '100%', borderRadius: 8, border: '1px solid #374151', background: '#020617', color: '#fff', padding: '8px 10px' }}
            />
            <button
              type="submit"
              disabled={!commentDraft.trim() || commentBusy}
              style={{ borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff', padding: '8px 12px' }}
            >
              {commentBusy ? 'Posting…' : 'Post comment'}
            </button>
          </form>
        </aside>
      </section>
    </main>
  );
}
