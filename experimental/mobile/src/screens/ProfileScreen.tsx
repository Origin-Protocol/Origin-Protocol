import React, { useEffect, useState } from 'react';
import { View, Text, Image, TouchableOpacity, StyleSheet, ScrollView, ActivityIndicator } from 'react-native';
import { usersApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { User } from '../types';

export default function ProfileScreen() {
  const { user: me, logout } = useAuth();
  const [profile, setProfile] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!me?.id) { setLoading(false); return; }
    usersApi.getProfile(me.id).then(({ user }) => {
      setProfile(user);
      setLoading(false);
    }).catch((e: Error) => {
      setError(e.message);
      setLoading(false);
    });
  }, [me?.id]);

  if (!me) {
    return (
      <View style={styles.center}>
        <Text>You are not logged in.</Text>
      </View>
    );
  }

  if (loading) return <ActivityIndicator style={styles.loader} />;
  if (error) return <Text style={styles.error}>Error: {error}</Text>;
  if (!profile) return <Text>User not found.</Text>;

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <View style={styles.header}>
        <View style={styles.avatar}>
          {profile.avatarUrl
            ? <Image source={{ uri: profile.avatarUrl }} style={styles.avatarImg} />
            : <Text style={styles.avatarEmoji}>👤</Text>
          }
        </View>
        <View>
          <Text style={styles.displayName}>{profile.displayName}</Text>
          <Text style={styles.username}>@{profile.username}</Text>
          {profile.creatorKeyId && (
            <Text style={styles.verified}>✅ Origin-verified creator</Text>
          )}
        </View>
      </View>
      {profile.bio ? <Text style={styles.bio}>{profile.bio}</Text> : null}

      <TouchableOpacity style={styles.logoutBtn} onPress={() => void logout()}>
        <Text style={styles.logoutText}>Log out</Text>
      </TouchableOpacity>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { padding: 16, paddingBottom: 80 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  loader: { flex: 1 },
  error: { color: 'red', margin: 16 },
  header: { flexDirection: 'row', alignItems: 'center', gap: 12, marginBottom: 12 },
  avatar: { width: 64, height: 64, borderRadius: 32, backgroundColor: '#ddd', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' },
  avatarImg: { width: 64, height: 64 },
  avatarEmoji: { fontSize: 32 },
  displayName: { fontSize: 18, fontWeight: 'bold' },
  username: { color: '#666' },
  verified: { color: 'green', fontSize: 12 },
  bio: { color: '#444', marginBottom: 12 },
  logoutBtn: { borderWidth: 1, borderColor: '#ccc', borderRadius: 8, padding: 12, alignItems: 'center', marginTop: 16 },
  logoutText: { color: '#333' },
});
