import React, { useEffect, useState, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  TextInput,
  ActivityIndicator,
  SafeAreaView,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { Video, ResizeMode } from 'expo-av';
import { useRoute, RouteProp, useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { videosApi } from '../api/client';
import { VideoMeta, Comment, RootStackParamList } from '../types';
import { colors, spacing, radius, fontSize, shadow } from '../styles/tokens';

type RouteParams = RouteProp<RootStackParamList, 'VideoDetail'>;
type Nav = NativeStackNavigationProp<RootStackParamList>;

export default function VideoDetailScreen() {
  const route     = useRoute<RouteParams>();
  const navigation = useNavigation<Nav>();
  const { videoId } = route.params;

  const videoRef = useRef<Video>(null);

  const [video, setVideo]           = useState<VideoMeta | null>(null);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState<string | null>(null);
  const [liked, setLiked]           = useState(false);
  const [likeCount, setLikeCount]   = useState(0);
  const [comments, setComments]     = useState<Comment[]>([]);
  const [commentText, setCommentText] = useState('');
  const [posting, setPosting]       = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const [{ video: v }, { comments: c }] = await Promise.all([
          videosApi.get(videoId),
          videosApi.getComments(videoId),
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
  }, [videoId]);

  async function handleLike() {
    try {
      const res = await videosApi.like(videoId);
      setLiked(res.liked);
      setLikeCount((n) => res.liked ? n + 1 : Math.max(0, n - 1));
    } catch {
      // not logged in
    }
  }

  async function handlePostComment() {
    const text = commentText.trim();
    if (!text) return;
    setPosting(true);
    try {
      const res = await videosApi.postComment(videoId, text);
      setComments((prev) => [res.comment, ...prev]);
      setCommentText('');
    } catch {
      // not logged in
    } finally {
      setPosting(false);
    }
  }

  if (loading) {
    return (
      <SafeAreaView style={styles.safe}>
        <TouchableOpacity style={styles.back} onPress={() => navigation.goBack()}>
          <Text style={styles.backText}>← Back</Text>
        </TouchableOpacity>
        <View style={styles.skPlayer} />
        <View style={styles.skBody}>
          <View style={[styles.skLine, { width: '60%', height: 18 }]} />
          <View style={[styles.skLine, { width: '35%', height: 13, marginTop: spacing[2] }]} />
        </View>
      </SafeAreaView>
    );
  }

  if (error || !video) {
    return (
      <SafeAreaView style={styles.safe}>
        <TouchableOpacity style={styles.back} onPress={() => navigation.goBack()}>
          <Text style={styles.backText}>← Back</Text>
        </TouchableOpacity>
        <View style={styles.errorWrap}>
          <Text style={styles.errorText}>⚠ {error ?? 'Video not found.'}</Text>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.safe}>
      <KeyboardAvoidingView
        style={{ flex: 1 }}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      >
        <ScrollView contentContainerStyle={styles.scroll}>
          {/* Back */}
          <TouchableOpacity style={styles.back} onPress={() => navigation.goBack()}>
            <Text style={styles.backText}>← Back to feed</Text>
          </TouchableOpacity>

          {/* Video player */}
          <View style={styles.playerCard}>
            <Video
              ref={videoRef}
              source={{ uri: video.videoUrl }}
              style={styles.player}
              useNativeControls
              resizeMode={ResizeMode.CONTAIN}
            />
            <View style={styles.playerBody}>
              {/* Title + like */}
              <View style={styles.titleRow}>
                <Text style={styles.videoTitle} numberOfLines={3}>{video.title}</Text>
                <TouchableOpacity
                  onPress={() => void handleLike()}
                  style={[styles.likeBtn, liked && styles.likeBtnActive]}
                  accessibilityLabel={liked ? 'Unlike' : 'Like'}
                >
                  <Text style={[styles.likeHeart, liked && styles.likeHeartActive]}>
                    {liked ? '♥' : '♡'}
                  </Text>
                  <Text style={[styles.likeCount, liked && styles.likeCountActive]}>
                    {likeCount.toLocaleString()}
                  </Text>
                </TouchableOpacity>
              </View>

              {/* Origin badge */}
              {video.originVerified && (
                <View style={styles.badge}>
                  <Text style={styles.badgeText}>✓ Origin verified</Text>
                </View>
              )}

              {/* Description */}
              {video.description ? (
                <Text style={styles.description}>{video.description}</Text>
              ) : null}

              {/* Stats */}
              <View style={styles.stats}>
                <Text style={styles.stat}>◉ {video.viewCount.toLocaleString()} views</Text>
                <Text style={styles.stat}>◎ {video.commentCount.toLocaleString()} comments</Text>
                <Text style={[styles.stat, { marginLeft: 'auto' }]}>
                  {new Date(video.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                </Text>
              </View>
            </View>
          </View>

          {/* Comments */}
          <Text style={styles.sectionTitle}>Comments</Text>

          {/* Post comment */}
          <View style={styles.commentInput}>
            <TextInput
              style={styles.input}
              value={commentText}
              onChangeText={setCommentText}
              placeholder="Add a comment…"
              placeholderTextColor={colors.muted}
              returnKeyType="send"
              onSubmitEditing={() => void handlePostComment()}
            />
            <TouchableOpacity
              style={[styles.postBtn, (!commentText.trim() || posting) && styles.postBtnDisabled]}
              onPress={() => void handlePostComment()}
              disabled={!commentText.trim() || posting}
            >
              {posting
                ? <ActivityIndicator color="#fff" size="small" />
                : <Text style={styles.postBtnText}>Post</Text>
              }
            </TouchableOpacity>
          </View>

          {/* Comments list */}
          {comments.length === 0 ? (
            <View style={styles.empty}>
              <Text style={styles.emptyIcon}>💬</Text>
              <Text style={styles.emptyText}>No comments yet — be the first!</Text>
            </View>
          ) : (
            comments.map((c) => (
              <View key={c.id} style={styles.commentCard}>
                <Text style={styles.commentAuthor}>@{c.authorId}</Text>
                <Text style={styles.commentText}>{c.text}</Text>
                <Text style={styles.commentDate}>
                  {new Date(c.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                </Text>
              </View>
            ))
          )}
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: {
    flex:            1,
    backgroundColor: colors.bg,
  },
  scroll: {
    padding:       spacing[4],
    paddingBottom: 100,
  },
  back: {
    marginTop:    spacing[4],
    marginBottom: spacing[2],
  },
  backText: {
    fontSize: fontSize.sm,
    color:    colors.muted,
  },
  // Loading skeletons
  skPlayer: {
    height:          240,
    backgroundColor: colors.border,
  },
  skBody: {
    padding: spacing[4],
  },
  skLine: {
    backgroundColor: colors.surface2,
    borderRadius:    radius.sm,
  },
  // Error
  errorWrap: {
    margin:          spacing[4],
    backgroundColor: colors.errorSoft,
    borderRadius:    radius.md,
    padding:         spacing[4],
  },
  errorText: {
    color:    colors.error,
    fontSize: fontSize.sm,
  },
  // Player card
  playerCard: {
    backgroundColor: colors.surface,
    borderRadius:    radius.lg,
    borderWidth:     1,
    borderColor:     colors.border,
    overflow:        'hidden',
    marginBottom:    spacing[4],
    ...shadow.sm,
  },
  player: {
    width:           '100%',
    height:          240,
    backgroundColor: '#000',
  },
  playerBody: {
    padding: spacing[4],
    gap:     spacing[3],
  },
  titleRow: {
    flexDirection: 'row',
    alignItems:    'flex-start',
    gap:           spacing[3],
  },
  videoTitle: {
    flex:       1,
    fontSize:   fontSize.lg,
    fontWeight: '700',
    color:      colors.text,
    lineHeight: 24,
  },
  likeBtn: {
    alignItems:      'center',
    padding:         spacing[2],
    borderRadius:    radius.md,
    backgroundColor: colors.surface2,
    minWidth:        44,
    gap:             2,
    flexShrink:      0,
  },
  likeBtnActive: {
    backgroundColor: colors.errorSoft,
  },
  likeHeart: {
    fontSize: 20,
    color:    colors.muted,
  },
  likeHeartActive: {
    color: colors.error,
  },
  likeCount: {
    fontSize:   fontSize.xs,
    fontWeight: '600',
    color:      colors.muted,
  },
  likeCountActive: {
    color: colors.error,
  },
  badge: {
    alignSelf:         'flex-start',
    backgroundColor:   colors.successSoft,
    borderRadius:      radius.full,
    paddingHorizontal: spacing[2],
    paddingVertical:   3,
  },
  badgeText: {
    fontSize:      fontSize.xs,
    fontWeight:    '600',
    color:         colors.success,
    letterSpacing: 0.3,
    textTransform: 'uppercase',
  },
  description: {
    fontSize:   fontSize.sm,
    color:      colors.text2,
    lineHeight: 20,
  },
  stats: {
    flexDirection:  'row',
    alignItems:     'center',
    gap:            spacing[4],
    paddingTop:     spacing[2],
    borderTopWidth: 1,
    borderTopColor: colors.border,
  },
  stat: {
    fontSize: fontSize.xs,
    color:    colors.muted,
  },
  sectionTitle: {
    fontSize:     fontSize.md,
    fontWeight:   '600',
    color:        colors.text,
    marginBottom: spacing[3],
  },
  commentInput: {
    flexDirection: 'row',
    gap:           spacing[2],
    marginBottom:  spacing[4],
  },
  input: {
    flex:              1,
    backgroundColor:   colors.surface,
    borderWidth:       1.5,
    borderColor:       colors.border,
    borderRadius:      radius.md,
    paddingVertical:   8,
    paddingHorizontal: spacing[3],
    fontSize:          fontSize.sm,
    color:             colors.text,
  },
  postBtn: {
    backgroundColor: colors.primary,
    borderRadius:    radius.md,
    paddingHorizontal: spacing[4],
    alignItems:      'center',
    justifyContent:  'center',
    minWidth:        60,
  },
  postBtnDisabled: {
    opacity: 0.45,
  },
  postBtnText: {
    color:      '#fff',
    fontWeight: '700',
    fontSize:   fontSize.sm,
  },
  empty: {
    alignItems: 'center',
    padding:    spacing[8],
    gap:        spacing[3],
  },
  emptyIcon: {
    fontSize: 36,
    opacity:  0.45,
  },
  emptyText: {
    fontSize:  fontSize.sm,
    color:     colors.muted,
    textAlign: 'center',
  },
  commentCard: {
    backgroundColor: colors.surface,
    borderRadius:    radius.md,
    borderWidth:     1,
    borderColor:     colors.border,
    padding:         spacing[3],
    marginBottom:    spacing[3],
    gap:             spacing[1],
  },
  commentAuthor: {
    fontSize:   fontSize.sm,
    fontWeight: '600',
    color:      colors.text,
  },
  commentText: {
    fontSize:   fontSize.sm,
    color:      colors.text2,
    lineHeight: 19,
  },
  commentDate: {
    fontSize:  fontSize.xs,
    color:     colors.muted,
    marginTop: 2,
  },
});
