import React, { useState } from 'react';
import {
  View,
  Text,
  Image,
  TouchableOpacity,
  StyleSheet,
} from 'react-native';
import { VideoMeta } from '../types';
import { colors, spacing, radius, fontSize, shadow } from '../styles/tokens';

interface Props {
  video: VideoMeta;
  onLike?: () => void;
}

export default function VideoCard({ video, onLike }: Props) {
  const [liked, setLiked] = useState(false);

  function handleLike() {
    setLiked((v) => !v);
    onLike?.();
  }

  return (
    <View style={styles.card}>
      {/* Thumbnail / player placeholder */}
      <View style={styles.thumb}>
        {video.thumbnailUrl ? (
          <Image source={{ uri: video.thumbnailUrl }} style={styles.thumbImg} resizeMode="cover" />
        ) : (
          <View style={styles.thumbPlaceholder}>
            <Text style={styles.playIcon}>▷</Text>
          </View>
        )}
      </View>

      {/* Content area */}
      <View style={styles.body}>
        {/* Title + like button */}
        <View style={styles.titleRow}>
          <Text style={styles.title} numberOfLines={2}>{video.title}</Text>
          <TouchableOpacity
            onPress={handleLike}
            style={[styles.likeBtn, liked && styles.likeBtnActive]}
            accessibilityLabel={liked ? 'Unlike' : 'Like'}
          >
            <Text style={[styles.likeHeart, liked && styles.likeHeartActive]}>
              {liked ? '♥' : '♡'}
            </Text>
            <Text style={[styles.likeCount, liked && styles.likeCountActive]}>
              {(video.likeCount + (liked ? 1 : 0)).toLocaleString()}
            </Text>
          </TouchableOpacity>
        </View>

        {/* Description */}
        {video.description ? (
          <Text style={styles.desc} numberOfLines={2}>{video.description}</Text>
        ) : null}

        {/* Origin-verified badge */}
        {video.originVerified && (
          <View style={styles.badge}>
            <Text style={styles.badgeText}>✓ Origin verified</Text>
          </View>
        )}

        {/* Stats row */}
        <View style={styles.stats}>
          <Text style={styles.stat}>◉ {video.viewCount.toLocaleString()} views</Text>
          <Text style={styles.stat}>◎ {video.commentCount.toLocaleString()}</Text>
          <Text style={[styles.stat, { marginLeft: 'auto' }]}>
            {new Date(video.createdAt).toLocaleDateString(undefined, {
              month: 'short', day: 'numeric', year: 'numeric',
            })}
          </Text>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.surface,
    borderRadius:    radius.lg,
    marginBottom:    spacing[4],
    overflow:        'hidden',
    borderWidth:     1,
    borderColor:     colors.border,
    ...shadow.sm,
  },
  thumb: {
    width:  '100%',
    height: 220,
  },
  thumbImg: {
    width:  '100%',
    height: '100%',
  },
  thumbPlaceholder: {
    flex:            1,
    backgroundColor: '#111',
    alignItems:      'center',
    justifyContent:  'center',
  },
  playIcon: {
    fontSize: 44,
    color:    'rgba(255,255,255,0.3)',
  },
  body: {
    padding: spacing[4],
    gap:     spacing[2],
  },
  titleRow: {
    flexDirection:  'row',
    alignItems:     'flex-start',
    gap:            spacing[3],
  },
  title: {
    flex:       1,
    fontSize:   fontSize.md,
    fontWeight: '700',
    color:      colors.text,
    lineHeight: 22,
  },
  likeBtn: {
    alignItems:      'center',
    padding:         spacing[2],
    borderRadius:    radius.md,
    backgroundColor: colors.surface2,
    minWidth:        40,
    gap:             2,
  },
  likeBtnActive: {
    backgroundColor: colors.errorSoft,
  },
  likeHeart: {
    fontSize: 18,
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
  desc: {
    fontSize:   fontSize.sm,
    color:      colors.text2,
    lineHeight: 19,
  },
  badge: {
    alignSelf:       'flex-start',
    backgroundColor: colors.successSoft,
    borderRadius:    radius.full,
    paddingHorizontal: spacing[2],
    paddingVertical:   3,
  },
  badgeText: {
    fontSize:    fontSize.xs,
    fontWeight:  '600',
    color:       colors.success,
    letterSpacing: 0.3,
    textTransform: 'uppercase',
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
});
