import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { VideoMeta } from '../types';

interface Props {
  video: VideoMeta;
  onLike?: () => void;
}

export default function VideoCard({ video, onLike }: Props) {
  return (
    <View style={styles.card}>
      {/* Video thumbnail placeholder — swap for expo-av Video in production */}
      <View style={styles.videoPlaceholder}>
        <Text style={styles.playIcon}>▶</Text>
      </View>
      <View style={styles.info}>
        <Text style={styles.title} numberOfLines={2}>{video.title}</Text>
        {video.description ? (
          <Text style={styles.desc} numberOfLines={2}>{video.description}</Text>
        ) : null}
        {video.originVerified && (
          <Text style={styles.verified}>✅ Origin-verified</Text>
        )}
        <View style={styles.stats}>
          <Text style={styles.stat}>👁 {video.viewCount}</Text>
          <Text style={styles.stat}>💬 {video.commentCount}</Text>
          <TouchableOpacity onPress={onLike}>
            <Text style={styles.stat}>❤️ {video.likeCount}</Text>
          </TouchableOpacity>
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  card: { marginBottom: 16, borderBottomWidth: 1, borderColor: '#eee', paddingBottom: 12 },
  videoPlaceholder: {
    height: 220,
    backgroundColor: '#111',
    alignItems: 'center',
    justifyContent: 'center',
  },
  playIcon: { fontSize: 48, color: '#fff' },
  info: { paddingHorizontal: 12, paddingTop: 8 },
  title: { fontWeight: 'bold', fontSize: 15 },
  desc: { color: '#555', fontSize: 13, marginTop: 2 },
  verified: { color: 'green', fontSize: 12, marginTop: 2 },
  stats: { flexDirection: 'row', gap: 12, marginTop: 6 },
  stat: { color: '#666', fontSize: 13 },
});
