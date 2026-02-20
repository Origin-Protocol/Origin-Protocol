import React, { useEffect, useState, useCallback } from 'react';
import {
  View,
  FlatList,
  Text,
  ActivityIndicator,
  StyleSheet,
  TouchableOpacity,
  ListRenderItemInfo,
} from 'react-native';
import { feedApi, videosApi } from '../api/client';
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

  async function handleLike(video: VideoMeta) {
    try {
      const res = await videosApi.like(video.id);
      setVideos((prev) =>
        prev.map((v) =>
          v.id === video.id
            ? { ...v, likeCount: res.liked ? v.likeCount + 1 : Math.max(0, v.likeCount - 1) }
            : v
        )
      );
    } catch {
      // ignore
    }
  }

  function renderItem({ item }: ListRenderItemInfo<VideoMeta>) {
    return <VideoCard video={item} onLike={() => void handleLike(item)} />;
  }

  if (error) {
    return (
      <View style={styles.center}>
        <Text style={styles.error}>Error: {error}</Text>
      </View>
    );
  }

  return (
    <FlatList
      data={videos}
      keyExtractor={(v) => v.id}
      renderItem={renderItem}
      onEndReached={() => void loadMore()}
      onEndReachedThreshold={0.4}
      ListEmptyComponent={
        loading ? null : <Text style={styles.empty}>No videos yet — be the first to upload!</Text>
      }
      ListFooterComponent={loading ? <ActivityIndicator style={styles.loader} /> : null}
      contentContainerStyle={styles.list}
    />
  );
}

const styles = StyleSheet.create({
  list: { paddingBottom: 80 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  error: { color: 'red' },
  empty: { textAlign: 'center', marginTop: 40, color: '#666' },
  loader: { padding: 16 },
});
