import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  Alert,
} from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import { videosApi } from '../api/client';
import { VideoMeta } from '../types';

export default function UploadScreen() {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [bundleId, setBundleId] = useState('');
  const [videoUri, setVideoUri] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<VideoMeta | null>(null);

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
    }
  }

  async function handleUpload() {
    if (!videoUri) { Alert.alert('No video selected'); return; }
    if (!title.trim()) { Alert.alert('Title is required'); return; }

    setUploading(true);
    try {
      const { video } = await videosApi.upload({
        uri: videoUri,
        title: title.trim(),
        description: description.trim() || undefined,
        originBundleId: bundleId.trim() || undefined,
      });
      setResult(video);
    } catch (e) {
      Alert.alert('Upload failed', (e as Error).message);
    } finally {
      setUploading(false);
    }
  }

  if (result) {
    return (
      <View style={styles.center}>
        <Text style={styles.title}>✅ Upload successful!</Text>
        <Text>{result.title}</Text>
        {result.originVerified && (
          <Text style={styles.verified}>✅ Origin Protocol ownership verified</Text>
        )}
        <TouchableOpacity style={styles.btn} onPress={() => setResult(null)}>
          <Text style={styles.btnText}>Upload another</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.heading}>Upload a video</Text>

      <TouchableOpacity style={styles.picker} onPress={() => void pickVideo()}>
        <Text>{videoUri ? '🎬 Video selected — tap to change' : '📂 Pick a video from library'}</Text>
      </TouchableOpacity>

      <Text style={styles.label}>Title *</Text>
      <TextInput
        style={styles.input}
        value={title}
        onChangeText={setTitle}
        maxLength={150}
        placeholder="Give your video a title"
      />

      <Text style={styles.label}>Description</Text>
      <TextInput
        style={[styles.input, styles.multiline]}
        value={description}
        onChangeText={setDescription}
        maxLength={500}
        multiline
        numberOfLines={3}
        placeholder="Optional description"
      />

      <Text style={styles.label}>Origin Bundle ID</Text>
      <TextInput
        style={styles.input}
        value={bundleId}
        onChangeText={setBundleId}
        placeholder="Optional — links to your Origin Protocol proof"
      />

      <TouchableOpacity
        style={[styles.btn, uploading && styles.btnDisabled]}
        onPress={() => void handleUpload()}
        disabled={uploading}
      >
        <Text style={styles.btnText}>{uploading ? 'Uploading…' : 'Upload'}</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, paddingBottom: 80 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 8 },
  heading: { fontSize: 20, fontWeight: 'bold', marginBottom: 16 },
  title: { fontSize: 18, fontWeight: 'bold' },
  verified: { color: 'green' },
  picker: { borderWidth: 1, borderColor: '#ccc', borderRadius: 8, padding: 12, marginBottom: 16, borderStyle: 'dashed' },
  label: { fontWeight: '600', marginBottom: 4, marginTop: 12 },
  input: { borderWidth: 1, borderColor: '#ccc', borderRadius: 8, padding: 10, fontSize: 15 },
  multiline: { minHeight: 80, textAlignVertical: 'top' },
  btn: { backgroundColor: '#000', borderRadius: 8, padding: 14, alignItems: 'center', marginTop: 20 },
  btnDisabled: { opacity: 0.5 },
  btnText: { color: '#fff', fontWeight: 'bold', fontSize: 16 },
});
