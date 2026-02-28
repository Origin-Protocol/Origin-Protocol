import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  Alert,
  ActivityIndicator,
  SafeAreaView,
  Platform,
} from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import { videosApi } from '../api/client';
import { VideoMeta } from '../types';
import { colors, spacing, radius, fontSize, shadow } from '../styles/tokens';

export default function UploadScreen() {
  const [title, setTitle]           = useState('');
  const [description, setDescription] = useState('');
  const [bundleId, setBundleId]     = useState('');
  const [videoUri, setVideoUri]     = useState<string | null>(null);
  const [videoName, setVideoName]   = useState<string | null>(null);
  const [uploading, setUploading]   = useState(false);
  const [result, setResult]         = useState<VideoMeta | null>(null);

  async function pickVideo() {
    const perm = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (!perm.granted) {
      Alert.alert('Permission required', 'Media library access is needed to pick a video.');
      return;
    }

    const res = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Videos,
      allowsEditing: false,
      quality: 1,
    });

    if (!res.canceled && res.assets[0]) {
      setVideoUri(res.assets[0].uri);
      const parts = res.assets[0].uri.split('/');
      setVideoName(parts[parts.length - 1] ?? 'video.mp4');
    }
  }

  async function handleUpload() {
    if (!videoUri) { Alert.alert('No video selected'); return; }
    if (!title.trim()) { Alert.alert('Title is required'); return; }

    setUploading(true);
    try {
      const { video } = await videosApi.upload({
        uri:          videoUri,
        title:        title.trim(),
        description:  description.trim() || undefined,
        originBundleId: bundleId.trim() || undefined,
      });
      setResult(video);
    } catch (e) {
      Alert.alert('Upload failed', (e as Error).message);
    } finally {
      setUploading(false);
    }
  }

  /* ── Success state ─────────────────────────────────────────────────── */
  if (result) {
    return (
      <SafeAreaView style={styles.safe}>
        <View style={styles.successWrap}>
          <View style={styles.successIcon}>
            <Text style={styles.successCheck}>✓</Text>
          </View>
          <Text style={styles.successTitle}>Upload successful!</Text>
          <Text style={styles.successName}>{result.title}</Text>
          {result.originVerified && (
            <View style={styles.badge}>
              <Text style={styles.badgeText}>✓ Origin Protocol ownership verified</Text>
            </View>
          )}
          <TouchableOpacity
            style={[styles.btn, styles.btnOutline, { marginTop: spacing[6] }]}
            onPress={() => { setResult(null); setVideoUri(null); setVideoName(null); setTitle(''); setDescription(''); setBundleId(''); }}
          >
            <Text style={styles.btnOutlineText}>Upload another video</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  /* ── Upload form ───────────────────────────────────────────────────── */
  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        {/* Header */}
        <View style={styles.header}>
          <Text style={styles.heading}>Upload a video</Text>
          <Text style={styles.subheading}>
            Share your authenticated content with the Origin Social community.
          </Text>
        </View>

        {/* Pick video zone */}
        <TouchableOpacity style={styles.dropZone} onPress={() => void pickVideo()}>
          <Text style={styles.dropIcon}>⊕</Text>
          {videoUri ? (
            <>
              <Text style={styles.dropTitle}>{videoName ?? 'Video selected'}</Text>
              <Text style={styles.dropSub}>Tap to change</Text>
            </>
          ) : (
            <>
              <Text style={styles.dropTitle}>Pick a video from library</Text>
              <Text style={styles.dropSub}>MP4, MOV, and more</Text>
            </>
          )}
        </TouchableOpacity>

        {/* Title */}
        <View style={styles.field}>
          <Text style={styles.fieldLabel}>Title</Text>
          <TextInput
            style={styles.input}
            value={title}
            onChangeText={setTitle}
            placeholder="Give your video a title"
            placeholderTextColor={colors.muted}
            maxLength={150}
          />
        </View>

        {/* Description */}
        <View style={styles.field}>
          <Text style={styles.fieldLabel}>
            Description <Text style={styles.optional}>(optional)</Text>
          </Text>
          <TextInput
            style={[styles.input, styles.inputMulti]}
            value={description}
            onChangeText={setDescription}
            placeholder="Tell viewers about your video…"
            placeholderTextColor={colors.muted}
            maxLength={500}
            multiline
            numberOfLines={3}
            textAlignVertical="top"
          />
        </View>

        {/* Origin Bundle ID */}
        <View style={styles.field}>
          <Text style={styles.fieldLabel}>
            Origin Bundle ID <Text style={styles.optional}>(optional)</Text>
          </Text>
          <TextInput
            style={[styles.input, { fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' }]}
            value={bundleId}
            onChangeText={setBundleId}
            placeholder="Links to your Origin Protocol ownership proof"
            placeholderTextColor={colors.muted}
            autoCapitalize="none"
            autoCorrect={false}
          />
          <Text style={styles.hint}>
            Attach a verified ownership proof to this upload.
          </Text>
        </View>

        {/* Submit */}
        <TouchableOpacity
          style={[styles.btn, styles.btnPrimary, uploading && styles.btnDisabled]}
          onPress={() => void handleUpload()}
          disabled={uploading}
        >
          {uploading
            ? <ActivityIndicator color="#fff" size="small" />
            : <Text style={styles.btnPrimaryText}>Upload video</Text>
          }
        </TouchableOpacity>
      </ScrollView>
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
  header: {
    marginBottom: spacing[5],
    paddingTop:   spacing[3],
    gap:          spacing[1],
  },
  heading: {
    fontSize:      fontSize['2xl'],
    fontWeight:    '700',
    color:         colors.text,
    letterSpacing: -0.4,
  },
  subheading: {
    fontSize:   fontSize.sm,
    color:      colors.muted,
    lineHeight: 19,
  },
  dropZone: {
    borderWidth:     2,
    borderColor:     colors.border,
    borderStyle:     'dashed',
    borderRadius:    radius.lg,
    backgroundColor: colors.surface,
    padding:         spacing[8],
    alignItems:      'center',
    marginBottom:    spacing[5],
    gap:             spacing[2],
    ...shadow.sm,
  },
  dropIcon: {
    fontSize: 36,
    color:    colors.primary,
    marginBottom: spacing[2],
  },
  dropTitle: {
    fontSize:   fontSize.md,
    fontWeight: '600',
    color:      colors.text,
    textAlign:  'center',
  },
  dropSub: {
    fontSize:  fontSize.sm,
    color:     colors.muted,
    textAlign: 'center',
  },
  field: {
    marginBottom: spacing[4],
    gap:          spacing[2],
  },
  fieldLabel: {
    fontSize:   fontSize.sm,
    fontWeight: '600',
    color:      colors.text,
  },
  optional: {
    fontWeight: '400',
    color:      colors.muted,
    fontSize:   fontSize.xs,
  },
  input: {
    backgroundColor:   colors.surface,
    borderWidth:       1.5,
    borderColor:       colors.border,
    borderRadius:      radius.md,
    paddingVertical:   10,
    paddingHorizontal: spacing[3],
    fontSize:          fontSize.base,
    color:             colors.text,
  },
  inputMulti: {
    minHeight:         80,
    // textAlignVertical is Android-only; on iOS multiline TextInput
    // naturally starts at the top, so the visual result is the same.
    textAlignVertical: 'top',
  },
  hint: {
    fontSize:  fontSize.xs,
    color:     colors.muted,
    lineHeight: 16,
  },
  btn: {
    paddingVertical: spacing[3],
    borderRadius:    radius.md,
    alignItems:      'center',
    justifyContent:  'center',
    minHeight:       48,
  },
  btnPrimary: {
    backgroundColor: colors.primary,
  },
  btnPrimaryText: {
    color:      '#fff',
    fontWeight: '700',
    fontSize:   fontSize.md,
  },
  btnOutline: {
    borderWidth:     1.5,
    borderColor:     colors.border,
    backgroundColor: 'transparent',
  },
  btnOutlineText: {
    color:      colors.text2,
    fontWeight: '600',
    fontSize:   fontSize.base,
  },
  btnDisabled: {
    opacity: 0.5,
  },
  successWrap: {
    flex:            1,
    alignItems:      'center',
    justifyContent:  'center',
    padding:         spacing[6],
    backgroundColor: colors.bg,
  },
  successIcon: {
    width:           72,
    height:          72,
    borderRadius:    36,
    backgroundColor: colors.successSoft,
    alignItems:      'center',
    justifyContent:  'center',
    marginBottom:    spacing[4],
  },
  successCheck: {
    fontSize:   32,
    color:      colors.success,
    fontWeight: '700',
  },
  successTitle: {
    fontSize:     fontSize['2xl'],
    fontWeight:   '700',
    color:        colors.text,
    marginBottom: spacing[2],
  },
  successName: {
    fontSize:     fontSize.md,
    color:        colors.muted,
    marginBottom: spacing[4],
    textAlign:    'center',
  },
  badge: {
    alignSelf:         'center',
    backgroundColor:   colors.successSoft,
    borderRadius:      radius.full,
    paddingHorizontal: spacing[3],
    paddingVertical:   4,
  },
  badgeText: {
    fontSize:      fontSize.xs,
    fontWeight:    '600',
    color:         colors.success,
    letterSpacing: 0.3,
    textTransform: 'uppercase',
  },
});
