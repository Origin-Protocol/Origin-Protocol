import React, { useEffect, useState } from 'react';
import {
  View,
  Text,
  Image,
  TouchableOpacity,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
  SafeAreaView,
  TextInput,
  Alert,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { usersApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { User, RootStackParamList } from '../types';
import { colors, spacing, radius, fontSize, shadow } from '../styles/tokens';

type Nav = NativeStackNavigationProp<RootStackParamList>;

export default function ProfileScreen() {
  const { user: me, logout } = useAuth();
  const navigation = useNavigation<Nav>();
  const [profile, setProfile]   = useState<User | null>(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [editing, setEditing]   = useState(false);
  const [saving, setSaving]     = useState(false);
  const [editDisplayName, setEditDisplayName] = useState('');
  const [editBio, setEditBio]   = useState('');

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

  function startEdit() {
    if (!profile) return;
    setEditDisplayName(profile.displayName);
    setEditBio(profile.bio ?? '');
    setEditing(true);
  }

  async function saveEdit() {
    setSaving(true);
    try {
      const { user } = await usersApi.updateMe({
        displayName: editDisplayName.trim() || undefined,
        bio:         editBio.trim() || undefined,
      });
      setProfile(user);
      setEditing(false);
    } catch (e) {
      Alert.alert('Save failed', (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (!me) {
    return (
      <SafeAreaView style={styles.safe}>
        <View style={styles.empty}>
          <Text style={styles.emptyIcon}>◎</Text>
          <Text style={styles.emptyText}>You are not logged in.</Text>
        </View>
      </SafeAreaView>
    );
  }

  if (loading) {
    return (
      <SafeAreaView style={styles.safe}>
        {/* Skeleton */}
        <View style={styles.skHeader}>
          <View style={styles.skAvatar} />
          <View style={{ flex: 1, gap: spacing[2] }}>
            <View style={[styles.skLine, { width: '55%' }]} />
            <View style={[styles.skLine, { width: '35%', height: 12 }]} />
          </View>
        </View>
        <View style={styles.skBio} />
      </SafeAreaView>
    );
  }

  if (error) {
    return (
      <SafeAreaView style={styles.safe}>
        <View style={styles.errorWrap}>
          <Text style={styles.errorText}>⚠ {error}</Text>
        </View>
      </SafeAreaView>
    );
  }

  if (!profile) {
    return (
      <SafeAreaView style={styles.safe}>
        <View style={styles.empty}>
          <Text style={styles.emptyIcon}>◎</Text>
          <Text style={styles.emptyText}>User not found.</Text>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll}>
        {/* Header row */}
        <View style={styles.header}>
          {/* Avatar */}
          <View style={styles.avatar}>
            {profile.avatarUrl ? (
              <Image source={{ uri: profile.avatarUrl }} style={styles.avatarImg} />
            ) : (
              <Text style={styles.avatarFallback}>◎</Text>
            )}
          </View>

          {/* Name + username */}
          <View style={styles.nameBlock}>
            <Text style={styles.displayName} numberOfLines={1}>{profile.displayName}</Text>
            <Text style={styles.username}>@{profile.username}</Text>
            {profile.creatorKeyId && (
              <View style={styles.badge}>
                <Text style={styles.badgeText}>✓ Origin Protocol verified</Text>
              </View>
            )}
          </View>
        </View>

        {/* Bio */}
        {profile.bio ? (
          <View style={styles.bioBox}>
            <Text style={styles.bioText}>{profile.bio}</Text>
          </View>
        ) : null}

        {/* Edit form (inline) */}
        {editing ? (
          <View style={styles.editCard}>
            <Text style={styles.editHeading}>Edit profile</Text>
            <View style={styles.field}>
              <Text style={styles.fieldLabel}>Display name</Text>
              <TextInput
                style={styles.input}
                value={editDisplayName}
                onChangeText={setEditDisplayName}
                placeholder="Your Name"
                placeholderTextColor={colors.muted}
              />
            </View>
            <View style={styles.field}>
              <Text style={styles.fieldLabel}>
                Bio <Text style={styles.optional}>(optional)</Text>
              </Text>
              <TextInput
                style={[styles.input, styles.inputMulti]}
                value={editBio}
                onChangeText={setEditBio}
                placeholder="Tell people about yourself…"
                placeholderTextColor={colors.muted}
                multiline
                numberOfLines={3}
              />
            </View>
            <View style={styles.editActions}>
              <TouchableOpacity
                style={[styles.btn, styles.btnOutline]}
                onPress={() => setEditing(false)}
              >
                <Text style={styles.btnOutlineText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.btn, styles.btnPrimary, saving && styles.btnDisabled]}
                onPress={() => void saveEdit()}
                disabled={saving}
              >
                {saving
                  ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.btnPrimaryText}>Save</Text>
                }
              </TouchableOpacity>
            </View>
          </View>
        ) : (
          <View style={{ gap: spacing[3] }}>
            <View style={styles.actions}>
              <TouchableOpacity style={[styles.btn, styles.btnOutline, { flex: 1 }]} onPress={startEdit}>
                <Text style={styles.btnOutlineText}>Edit profile</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.btn, styles.btnGhost, { flex: 1 }]}
                onPress={() => void logout()}
              >
                <Text style={styles.btnGhostText}>Log out</Text>
              </TouchableOpacity>
            </View>
            <TouchableOpacity
              style={[styles.btn, styles.btnOutline, { width: '100%' }]}
              onPress={() => navigation.navigate('Help')}
            >
              <Text style={styles.btnOutlineText}>ⓘ  Help & Support</Text>
            </TouchableOpacity>
          </View>
        )}

        <View style={styles.divider} />

        {/* Videos section */}
        <Text style={styles.sectionTitle}>Videos</Text>
        <View style={styles.empty}>
          <Text style={styles.emptyIcon}>📹</Text>
          <Text style={styles.emptyText}>No videos yet.</Text>
        </View>
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
    flexDirection: 'row',
    alignItems:    'center',
    gap:           spacing[4],
    paddingTop:    spacing[4],
    marginBottom:  spacing[4],
  },
  avatar: {
    width:           72,
    height:          72,
    borderRadius:    36,
    backgroundColor: colors.surface2,
    alignItems:      'center',
    justifyContent:  'center',
    overflow:        'hidden',
    borderWidth:     2,
    borderColor:     colors.border,
    flexShrink:      0,
  },
  avatarImg: {
    width:  72,
    height: 72,
  },
  avatarFallback: {
    fontSize: 32,
    color:    colors.muted,
  },
  nameBlock: {
    flex:    1,
    gap:     4,
  },
  displayName: {
    fontSize:      fontSize.xl,
    fontWeight:    '700',
    color:         colors.text,
    letterSpacing: -0.3,
  },
  username: {
    fontSize: fontSize.sm,
    color:    colors.muted,
  },
  badge: {
    alignSelf:         'flex-start',
    backgroundColor:   colors.successSoft,
    borderRadius:      radius.full,
    paddingHorizontal: spacing[2],
    paddingVertical:   3,
    marginTop:         spacing[1],
  },
  badgeText: {
    fontSize:      fontSize.xs,
    fontWeight:    '600',
    color:         colors.success,
    letterSpacing: 0.3,
    textTransform: 'uppercase',
  },
  bioBox: {
    backgroundColor: colors.surface2,
    borderRadius:    radius.md,
    padding:         spacing[3],
    marginBottom:    spacing[4],
  },
  bioText: {
    fontSize:   fontSize.sm,
    color:      colors.text2,
    lineHeight: 20,
  },
  actions: {
    flexDirection: 'row',
    gap:           spacing[3],
    marginBottom:  spacing[4],
  },
  editCard: {
    backgroundColor: colors.surface,
    borderRadius:    radius.lg,
    padding:         spacing[4],
    borderWidth:     1,
    borderColor:     colors.border,
    marginBottom:    spacing[4],
    ...shadow.sm,
  },
  editHeading: {
    fontSize:     fontSize.md,
    fontWeight:   '700',
    color:        colors.text,
    marginBottom: spacing[4],
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
    backgroundColor:   colors.bg,
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
  editActions: {
    flexDirection: 'row',
    gap:           spacing[3],
  },
  btn: {
    paddingVertical:   spacing[3],
    paddingHorizontal: spacing[4],
    borderRadius:      radius.md,
    alignItems:        'center',
    justifyContent:    'center',
    minHeight:         44,
    flex:              1,
  },
  btnPrimary: {
    backgroundColor: colors.primary,
  },
  btnPrimaryText: {
    color:      '#fff',
    fontWeight: '700',
    fontSize:   fontSize.base,
  },
  btnOutline: {
    borderWidth:  1.5,
    borderColor:  colors.border,
    backgroundColor: 'transparent',
  },
  btnOutlineText: {
    color:      colors.text2,
    fontWeight: '600',
    fontSize:   fontSize.base,
  },
  btnGhost: {
    backgroundColor: 'transparent',
  },
  btnGhostText: {
    color:      colors.muted,
    fontWeight: '600',
    fontSize:   fontSize.base,
  },
  btnDisabled: {
    opacity: 0.5,
  },
  divider: {
    borderTopWidth: 1,
    borderTopColor: colors.border,
    marginVertical: spacing[5],
  },
  sectionTitle: {
    fontSize:     fontSize.md,
    fontWeight:   '600',
    color:        colors.text,
    marginBottom: spacing[3],
  },
  empty: {
    alignItems: 'center',
    padding:    spacing[10],
    gap:        spacing[3],
  },
  emptyIcon: {
    fontSize: 40,
    opacity:  0.45,
  },
  emptyText: {
    fontSize:  fontSize.sm,
    color:     colors.muted,
    textAlign: 'center',
    maxWidth:  220,
  },
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
  // Skeleton
  skHeader: {
    flexDirection: 'row',
    alignItems:    'center',
    gap:           spacing[4],
    padding:       spacing[4],
    paddingTop:    spacing[6],
  },
  skAvatar: {
    width:           72,
    height:          72,
    borderRadius:    36,
    backgroundColor: colors.border,
    flexShrink:      0,
  },
  skLine: {
    height:          16,
    backgroundColor: colors.surface2,
    borderRadius:    radius.sm,
  },
  skBio: {
    height:          60,
    backgroundColor: colors.surface2,
    borderRadius:    radius.md,
    margin:          spacing[4],
  },
});
