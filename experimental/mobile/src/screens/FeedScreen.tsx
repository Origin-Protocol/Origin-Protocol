import React, { useEffect, useState, useCallback } from 'react';
import {
  View,
  FlatList,
  Text,
  StyleSheet,
  TouchableOpacity,
  ListRenderItemInfo,
  SafeAreaView,
} from 'react-native';
import { feedApi, videosApi } from '../api/client';
import { VideoMeta } from '../types';
import VideoCard from '../components/VideoCard';
import { colors, spacing, radius, fontSize } from '../styles/tokens';

function SkeletonCard() {
  return (
    <View style={sk.card}>
      <View style={sk.thumb} />
      <View style={sk.body}>
        <View style={[sk.line, { width: '65%' }]} />
        <View style={[sk.line, { width: '40%', marginTop: spacing[2] }]} />
      </View>
    </View>
  );
}

const sk = StyleSheet.create({
  card: {
    backgroundColor: colors.surface,
    borderRadius:    radius.lg,
    marginBottom:    spacing[4],
    overflow:        'hidden',
    borderWidth:     1,
    borderColor:     colors.border,
  },
  thumb: {
    height:          200,
    backgroundColor: colors.border,
  },
  body: {
    padding: spacing[4],
  },
  line: {
    height:          14,
    backgroundColor: colors.surface2,
    borderRadius:    radius.sm,
  },
});

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
      // ignore — user may not be logged in
    }
  }

  function renderItem({ item }: ListRenderItemInfo<VideoMeta>) {
    return <VideoCard video={item} onLike={() => void handleLike(item)} />;
  }

  return (
    <SafeAreaView style={styles.safe}>
      <FlatList
        data={loading && videos.length === 0 ? [] : videos}
        keyExtractor={(v) => v.id}
        renderItem={renderItem}
        onEndReached={() => void loadMore()}
        onEndReachedThreshold={0.4}
        contentContainerStyle={styles.list}
        ListHeaderComponent={
          <View style={styles.header}>
            <Text style={styles.logo}>⬡</Text>
            <View>
              <Text style={styles.title}>Origin Social</Text>
              <Text style={styles.subtitle}>Authenticated creator content</Text>
            </View>
          </View>
        }
        ListEmptyComponent={
          loading ? (
            <>
              <SkeletonCard />
              <SkeletonCard />
              <SkeletonCard />
            </>
          ) : error ? (
            <View style={styles.errorWrap}>
              <Text style={styles.errorText}>⚠ {error}</Text>
            </View>
          ) : (
            <View style={styles.empty}>
              <Text style={styles.emptyIcon}>📹</Text>
              <Text style={styles.emptyText}>No videos yet — be the first to upload!</Text>
            </View>
          )
        }
        ListFooterComponent={
          !loading || videos.length === 0 ? null : (
            <View style={styles.footer}>
              <Text style={styles.footerText}>Loading…</Text>
            </View>
          )
        }
      />
      {!loading && !hasMore && videos.length > 0 && (
        <View style={styles.allCaughtUp}>
          <Text style={styles.allCaughtUpText}>You're all caught up ✓</Text>
        </View>
      )}
      {!loading && hasMore && videos.length > 0 && (
        <TouchableOpacity style={styles.loadMoreBtn} onPress={() => void loadMore()}>
          <Text style={styles.loadMoreText}>Load more</Text>
        </TouchableOpacity>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: {
    flex:            1,
    backgroundColor: colors.bg,
  },
  list: {
    padding:       spacing[4],
    paddingBottom: 100,
  },
  header: {
    flexDirection:  'row',
    alignItems:     'center',
    gap:            spacing[3],
    marginBottom:   spacing[5],
    paddingTop:     spacing[2],
  },
  logo: {
    fontSize: 28,
    color:    colors.primary,
  },
  title: {
    fontSize:      fontSize.xl,
    fontWeight:    '700',
    color:         colors.text,
    letterSpacing: -0.4,
  },
  subtitle: {
    fontSize:  fontSize.sm,
    color:     colors.muted,
    marginTop: 2,
  },
  errorWrap: {
    backgroundColor: colors.errorSoft,
    borderRadius:    radius.md,
    padding:         spacing[4],
    margin:          spacing[4],
  },
  errorText: {
    color:    colors.error,
    fontSize: fontSize.sm,
  },
  empty: {
    alignItems: 'center',
    padding:    spacing[12],
    gap:        spacing[3],
  },
  emptyIcon: {
    fontSize: 40,
    opacity:  0.45,
  },
  emptyText: {
    fontSize:   fontSize.sm,
    color:      colors.muted,
    textAlign:  'center',
    maxWidth:   220,
    lineHeight: 20,
  },
  footer: {
    padding:    spacing[5],
    alignItems: 'center',
  },
  footerText: {
    color:    colors.muted,
    fontSize: fontSize.sm,
  },
  allCaughtUp: {
    alignItems:    'center',
    paddingBottom: spacing[6],
  },
  allCaughtUpText: {
    fontSize: fontSize.sm,
    color:    colors.muted,
  },
  loadMoreBtn: {
    marginHorizontal: spacing[4],
    marginBottom:     spacing[6],
    paddingVertical:  spacing[3],
    borderRadius:     radius.md,
    borderWidth:      1.5,
    borderColor:      colors.border,
    alignItems:       'center',
  },
  loadMoreText: {
    fontSize:   fontSize.base,
    fontWeight: '600',
    color:      colors.text2,
  },
});
