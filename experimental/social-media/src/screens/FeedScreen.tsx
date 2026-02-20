import { useEffect, useState, useCallback } from 'react';
import { feedApi } from '../api/client';
import { VideoMeta } from '../types';
import VideoCard from '../components/VideoCard';

export default function FeedScreen() {
  const [videos, setVideos] = useState<VideoMeta[]>([]);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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

  if (error) return <p style={{ color: 'red' }}>Error: {error}</p>;

  return (
    <main style={{ maxWidth: 480, margin: '0 auto' }}>
      <h2>Feed</h2>
      {videos.map((v) => (
        <VideoCard key={v.id} video={v} />
      ))}
      {loading && <p>Loading…</p>}
      {!loading && hasMore && (
        <button onClick={() => void loadMore()}>Load more</button>
      )}
      {!hasMore && videos.length > 0 && <p>No more videos.</p>}
      {!loading && videos.length === 0 && <p>No videos yet — be the first to upload!</p>}
    </main>
  );
}
