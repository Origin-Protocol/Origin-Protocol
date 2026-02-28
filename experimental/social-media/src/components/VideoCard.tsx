import { VideoMeta } from '../types';
import { videosApi } from '../api/client';
import { useState } from 'react';

interface Props {
  video: VideoMeta;
}

export default function VideoCard({ video }: Props) {
  const [liked, setLiked]       = useState(false);
  const [likeCount, setLikeCount] = useState(video.likeCount);

  async function handleLike() {
    try {
      const res = await videosApi.like(video.id);
      setLiked(res.liked);
      setLikeCount((c) => res.liked ? c + 1 : Math.max(0, c - 1));
    } catch {
      // ignore — user may not be logged in
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
          <span>◎ {video.commentCount.toLocaleString()} comments</span>
          <span style={{ marginLeft: 'auto' }}>
            {new Date(video.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
          </span>
        </div>
      </div>
    </article>
  );
}
