import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  KeyboardAvoidingView,
  Platform,
  Alert,
  ScrollView,
  ActivityIndicator,
} from 'react-native';
import { useAuth } from '../hooks/useAuth';
import { colors, spacing, radius, fontSize, shadow } from '../styles/tokens';

type Mode = 'login' | 'register';

export default function LoginScreen() {
  const { login, register } = useAuth();
  const [mode, setMode]             = useState<Mode>('login');
  const [email, setEmail]           = useState('');
  const [password, setPassword]     = useState('');
  const [username, setUsername]     = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading]       = useState(false);

  async function handleSubmit() {
    if (!email || !password) {
      Alert.alert('Please fill in all required fields');
      return;
    }
    setLoading(true);
    try {
      if (mode === 'login') {
        await login(email, password);
      } else {
        if (!username) { Alert.alert('Username is required'); setLoading(false); return; }
        await register(username, email, password, displayName || undefined);
      }
    } catch (e) {
      Alert.alert('Error', (e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      style={styles.wrapper}
    >
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        {/* Brand header */}
        <View style={styles.brand}>
          <Text style={styles.logo}>⬡</Text>
          <Text style={styles.brandTitle}>Origin Social</Text>
          <Text style={styles.brandSub}>
            {mode === 'login' ? 'Sign in to your account' : 'Create your creator account'}
          </Text>
        </View>

        {/* Card */}
        <View style={styles.card}>
          {/* Mode toggle */}
          <View style={styles.toggle}>
            {(['login', 'register'] as Mode[]).map((m) => (
              <TouchableOpacity
                key={m}
                style={[styles.toggleBtn, mode === m && styles.toggleBtnActive]}
                onPress={() => setMode(m)}
              >
                <Text style={[styles.toggleText, mode === m && styles.toggleTextActive]}>
                  {m === 'login' ? 'Log in' : 'Create account'}
                </Text>
              </TouchableOpacity>
            ))}
          </View>

          {/* Register-only fields */}
          {mode === 'register' && (
            <>
              <View style={styles.field}>
                <Text style={styles.label}>Username</Text>
                <TextInput
                  style={styles.input}
                  value={username}
                  onChangeText={setUsername}
                  placeholder="your_handle"
                  autoCapitalize="none"
                  autoCorrect={false}
                  placeholderTextColor={colors.muted}
                />
              </View>
              <View style={styles.field}>
                <Text style={styles.label}>
                  Display name{' '}
                  <Text style={styles.optional}>(optional)</Text>
                </Text>
                <TextInput
                  style={styles.input}
                  value={displayName}
                  onChangeText={setDisplayName}
                  placeholder="Your Name"
                  placeholderTextColor={colors.muted}
                />
              </View>
            </>
          )}

          {/* Email */}
          <View style={styles.field}>
            <Text style={styles.label}>Email</Text>
            <TextInput
              style={styles.input}
              value={email}
              onChangeText={setEmail}
              placeholder="you@example.com"
              keyboardType="email-address"
              autoCapitalize="none"
              autoCorrect={false}
              placeholderTextColor={colors.muted}
            />
          </View>

          {/* Password */}
          <View style={styles.field}>
            <Text style={styles.label}>Password</Text>
            <TextInput
              style={styles.input}
              value={password}
              onChangeText={setPassword}
              placeholder="••••••••"
              secureTextEntry
              placeholderTextColor={colors.muted}
            />
          </View>

          {/* Submit */}
          <TouchableOpacity
            style={[styles.btn, loading && styles.btnDisabled]}
            onPress={() => void handleSubmit()}
            disabled={loading}
          >
            {loading
              ? <ActivityIndicator color="#fff" size="small" />
              : <Text style={styles.btnText}>
                  {mode === 'login' ? 'Log in' : 'Create account'}
                </Text>
            }
          </TouchableOpacity>
        </View>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  wrapper: {
    flex:            1,
    backgroundColor: colors.bg,
  },
  scroll: {
    flexGrow:        1,
    justifyContent:  'center',
    padding:         spacing[5],
  },
  brand: {
    alignItems:   'center',
    marginBottom: spacing[8],
  },
  logo: {
    fontSize:     44,
    color:        colors.primary,
    marginBottom: spacing[2],
  },
  brandTitle: {
    fontSize:      fontSize['2xl'],
    fontWeight:    '800',
    color:         colors.text,
    letterSpacing: -0.5,
  },
  brandSub: {
    fontSize:   fontSize.base,
    color:      colors.muted,
    marginTop:  spacing[1],
  },
  card: {
    backgroundColor: colors.surface,
    borderRadius:    radius.lg,
    padding:         spacing[5],
    borderWidth:     1,
    borderColor:     colors.border,
    ...shadow.sm,
  },
  toggle: {
    flexDirection:   'row',
    backgroundColor: colors.surface2,
    borderRadius:    radius.md,
    padding:         4,
    marginBottom:    spacing[5],
    gap:             4,
  },
  toggleBtn: {
    flex:          1,
    paddingVertical: 8,
    alignItems:    'center',
    borderRadius:  radius.sm,
  },
  toggleBtnActive: {
    backgroundColor: colors.surface,
    shadowColor:     '#000',
    shadowOffset:    { width: 0, height: 1 },
    shadowOpacity:   0.06,
    shadowRadius:    2,
    elevation:       1,
  },
  toggleText: {
    fontSize:   fontSize.sm,
    fontWeight: '600',
    color:      colors.muted,
  },
  toggleTextActive: {
    color: colors.primary,
  },
  field: {
    marginBottom: spacing[4],
    gap:          spacing[2],
  },
  label: {
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
    backgroundColor: colors.bg,
    borderWidth:     1.5,
    borderColor:     colors.border,
    borderRadius:    radius.md,
    paddingVertical:   Platform.OS === 'ios' ? 12 : 10,
    paddingHorizontal: spacing[3],
    fontSize:        fontSize.base,
    color:           colors.text,
  },
  btn: {
    backgroundColor: colors.primary,
    borderRadius:    radius.md,
    paddingVertical: spacing[3],
    alignItems:      'center',
    justifyContent:  'center',
    marginTop:       spacing[2],
    minHeight:       48,
  },
  btnDisabled: {
    opacity: 0.5,
  },
  btnText: {
    color:      '#fff',
    fontWeight: '700',
    fontSize:   fontSize.base,
  },
});
