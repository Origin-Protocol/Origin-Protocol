import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  ScrollView,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../types';
import { colors, spacing, radius, fontSize, shadow } from '../styles/tokens';

type Nav = NativeStackNavigationProp<RootStackParamList>;

const FEATURES = [
  {
    icon: '🔐',
    title: 'Verified ownership',
    body: 'Every video carries a cryptographic Origin Protocol proof — viewers always know who created it.',
  },
  {
    icon: '🎬',
    title: 'Authentic content',
    body: 'Only verified creators can upload. No deepfakes, no impersonators — just real, authenticated work.',
  },
  {
    icon: '🌐',
    title: 'Creator tools',
    body: 'Upload, share, and reach your audience on open, transparent infrastructure.',
  },
];

export default function LandingScreen() {
  const navigation = useNavigation<Nav>();

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Hero */}
        <View style={styles.hero}>
          <Text style={styles.logo}>⬡</Text>
          <Text style={styles.heroTitle}>Origin Social</Text>
          <Text style={styles.heroSub}>
            A creator platform where every video carries provable ownership via Origin Protocol.
          </Text>
          <TouchableOpacity
            style={[styles.btn, styles.btnPrimary]}
            onPress={() => navigation.navigate('Register')}
          >
            <Text style={styles.btnPrimaryText}>Get started free</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.btn, styles.btnOutline, { marginTop: spacing[3] }]}
            onPress={() => navigation.navigate('Login')}
          >
            <Text style={styles.btnOutlineText}>Log in</Text>
          </TouchableOpacity>
        </View>

        {/* Features */}
        <View style={styles.features}>
          {FEATURES.map((f) => (
            <View key={f.title} style={styles.featureCard}>
              <Text style={styles.featureIcon}>{f.icon}</Text>
              <View style={styles.featureBody}>
                <Text style={styles.featureTitle}>{f.title}</Text>
                <Text style={styles.featureText}>{f.body}</Text>
              </View>
            </View>
          ))}
        </View>

        <Text style={styles.footer}>
          By signing up you agree to the Origin Social terms of service.
        </Text>
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
    flexGrow: 1,
    padding:  spacing[5],
  },
  hero: {
    alignItems:    'center',
    paddingTop:    spacing[10],
    paddingBottom: spacing[10],
  },
  logo: {
    fontSize:     52,
    color:        colors.primary,
    marginBottom: spacing[4],
  },
  heroTitle: {
    fontSize:      fontSize['3xl'],
    fontWeight:    '800',
    color:         colors.text,
    letterSpacing: -0.6,
    marginBottom:  spacing[3],
  },
  heroSub: {
    fontSize:     fontSize.md,
    color:        colors.text2,
    textAlign:    'center',
    maxWidth:     280,
    lineHeight:   22,
    marginBottom: spacing[8],
  },
  btn: {
    width:           '100%',
    paddingVertical: spacing[3],
    borderRadius:    radius.full,
    alignItems:      'center',
    minHeight:       48,
    justifyContent:  'center',
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
    borderWidth:  1.5,
    borderColor:  colors.border,
    backgroundColor: 'transparent',
  },
  btnOutlineText: {
    color:      colors.text2,
    fontWeight: '600',
    fontSize:   fontSize.base,
  },
  features: {
    gap: spacing[3],
  },
  featureCard: {
    flexDirection:   'row',
    gap:             spacing[4],
    backgroundColor: colors.surface,
    borderRadius:    radius.lg,
    padding:         spacing[4],
    borderWidth:     1,
    borderColor:     colors.border,
    alignItems:      'flex-start',
    ...shadow.sm,
  },
  featureIcon: {
    fontSize:   28,
    lineHeight: 34,
    flexShrink: 0,
  },
  featureBody: {
    flex: 1,
    gap:  spacing[1],
  },
  featureTitle: {
    fontSize:   fontSize.md,
    fontWeight: '700',
    color:      colors.text,
  },
  featureText: {
    fontSize:   fontSize.sm,
    color:      colors.text2,
    lineHeight: 19,
  },
  footer: {
    fontSize:  fontSize.xs,
    color:     colors.muted,
    textAlign: 'center',
    marginTop: spacing[8],
  },
});
