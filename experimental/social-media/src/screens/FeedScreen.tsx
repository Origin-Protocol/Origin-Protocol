import { useEffect, useState, useCallback } from 'react';
import { feedApi } from '../api/client';
import { VideoMeta } from '../types';
import VideoCard from '../components/VideoCard';

function SkeletonCard() {
  return (
    <div className="card" style={{ marginBottom: 'var(--sp-4)', overflow: 'hidden' }}>
      <div className="skeleton" style={{ height: 200 }} />
      <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-2)' }}>
        <div className="skeleton" style={{ height: 16, width: '70%' }} />
        <div className="skeleton" style={{ height: 12, width: '45%' }} />
      </div>
    </div>
  );
}

export default function FeedScreen() {
  const [videos, setVideos]   = useState<VideoMeta[]>([]);
  const [page, setPage]       = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;
    setLoading(true);
    try {
      const data = await feedApi.get(page);
      setVideos((prev) => [...prev, ...data.items]);
      setHasMore(data.hasMore);
      setPage((p) => p + 1);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [loading, hasMore, page]);

  useEffect(() => {
    void loadMore();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <main className="page">
      {/* Header */}
      <header style={{
        display:       'flex',
        alignItems:    'center',
        gap:           'var(--sp-3)',
        marginBottom:  'var(--sp-5)',
        paddingTop:    'var(--sp-4)',
      }}>
        <span style={{ fontSize: 28, lineHeight: 1 }}>⬡</span>
        <div>
          <h1 className="page-title" style={{ fontSize: 20 }}>Origin Social</h1>
          <p className="page-lead" style={{ fontSize: 13 }}>Authenticated creator content</p>
        </div>
      </header>

      {/* Error */}
      {error && (
        <div className="inline-error" style={{ marginBottom: 'var(--sp-4)' }}>
          ⚠ {error}
        </div>
      )}

      {/* Skeleton on first load */}
      {loading && videos.length === 0 && (
        <>
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </>
      )}

      {/* Video list */}
      {videos.map((v) => (
        <VideoCard key={v.id} video={v} />
      ))}

      {/* Loading more */}
      {loading && videos.length > 0 && (
        <div className="loading-row" style={{ justifyContent: 'center' }}>
          <span className="spinner" />
          Loading…
        </div>
      )}

      {/* Load more button */}
      {!loading && hasMore && videos.length > 0 && (
        <button
          className="btn btn--outline btn--full"
          onClick={() => void loadMore()}
          style={{ marginTop: 'var(--sp-2)' }}
        >
          Load more
        </button>
      )}

      {/* End of feed */}
      {!hasMore && videos.length > 0 && (
        <p style={{
          textAlign:    'center',
          color:        'var(--color-text-muted)',
          fontSize:     13,
          paddingTop:   'var(--sp-4)',
          paddingBottom:'var(--sp-4)',
        }}>
          You're all caught up ✓
        </p>
      )}

      {/* Empty state */}
      {!loading && videos.length === 0 && !error && (
        <div className="empty-state">
          <span className="empty-state-icon">📹</span>
          <p>No videos yet — be the first to upload!</p>
          <a className="btn btn--primary" href="/upload">Upload now</a>
        </div>
      )}
    </main>
  );
}
