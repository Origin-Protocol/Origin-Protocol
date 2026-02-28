import React, { useState } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  ScrollView,
  Linking,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { RootStackParamList } from '../types';
import { colors, spacing, radius, fontSize, shadow } from '../styles/tokens';

type Nav = NativeStackNavigationProp<RootStackParamList>;

const FAQS = [
  {
    q: 'What is Origin Social?',
    a: 'Origin Social is a video-sharing platform for verified creators. Every piece of content is linked to an on-chain Origin Protocol proof, so viewers always know who owns and created the work.',
  },
  {
    q: 'What is Origin Protocol?',
    a: 'Origin Protocol is a set of cryptographic tools and smart contracts that let creators prove ownership of digital content. A creator registers their key, signs their work, and anyone can independently verify the signature on-chain.',
  },
  {
    q: 'How do I become Origin-verified?',
    a: 'Go to your profile, tap "Edit profile", and add your Origin Bundle ID. The platform checks your key status and marks your account as verified. Full documentation is at origin.network/docs.',
  },
  {
    q: 'How do I upload a video?',
    a: 'Tap the Upload tab in the bottom navigation. Select a video from your device, add a title and optional description, then press Upload. If your account is Origin-verified, the video will carry an ownership proof badge automatically.',
  },
  {
    q: 'Can I delete a video?',
    a: 'Yes. Open the video and use the options menu to delete it. The on-chain proof remains on the ledger — only the hosted file is removed.',
  },
  {
    q: 'Are my videos public?',
    a: 'All uploaded videos are public on Origin Social. Private and unlisted video options are on the roadmap.',
  },
  {
    q: 'How do I report inappropriate content?',
    a: 'Use the options menu on any video to report it. Our moderation team reviews reports within 24 hours.',
  },
];

function FaqItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);

  return (
    <View style={styles.faqCard}>
      <TouchableOpacity
        style={styles.faqHeader}
        onPress={() => setOpen((v) => !v)}
        accessibilityRole="button"
        accessibilityState={{ expanded: open }}
      >
        <Text style={styles.faqQ} numberOfLines={open ? undefined : 2}>{q}</Text>
        <Text style={[styles.faqToggle, open && styles.faqToggleOpen]}>+</Text>
      </TouchableOpacity>
      {open && (
        <View style={styles.faqBody}>
          <Text style={styles.faqA}>{a}</Text>
        </View>
      )}
    </View>
  );
}

export default function HelpScreen() {
  const navigation = useNavigation<Nav>();

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.scroll} showsVerticalScrollIndicator={false}>
        {/* Back */}
        <TouchableOpacity style={styles.back} onPress={() => navigation.goBack()}>
          <Text style={styles.backText}>← Back</Text>
        </TouchableOpacity>

        {/* Header */}
        <Text style={styles.title}>Help & Support</Text>
        <Text style={styles.subtitle}>
          Frequently asked questions and guides for Origin Social.
        </Text>

        <Text style={styles.sectionTitle}>Frequently asked questions</Text>

        {FAQS.map((f) => <FaqItem key={f.q} q={f.q} a={f.a} />)}

        {/* Contact card */}
        <View style={styles.contactCard}>
          <Text style={styles.contactIcon}>✉</Text>
          <Text style={styles.contactHeading}>Still need help?</Text>
          <Text style={styles.contactBody}>
            Reach the Origin Social team at support@origin.network
          </Text>
          <TouchableOpacity
            style={[styles.btn, styles.btnOutline]}
            onPress={() => void Linking.openURL('https://origin.network/docs')}
          >
            <Text style={styles.btnOutlineText}>View full documentation</Text>
          </TouchableOpacity>
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
  back: {
    marginTop:    spacing[4],
    marginBottom: spacing[4],
  },
  backText: {
    fontSize: fontSize.sm,
    color:    colors.muted,
  },
  title: {
    fontSize:      fontSize['2xl'],
    fontWeight:    '700',
    color:         colors.text,
    letterSpacing: -0.4,
    marginBottom:  spacing[1],
  },
  subtitle: {
    fontSize:     fontSize.sm,
    color:        colors.muted,
    lineHeight:   19,
    marginBottom: spacing[6],
  },
  sectionTitle: {
    fontSize:     fontSize.md,
    fontWeight:   '600',
    color:        colors.text,
    marginBottom: spacing[3],
  },
  faqCard: {
    backgroundColor: colors.surface,
    borderRadius:    radius.lg,
    borderWidth:     1,
    borderColor:     colors.border,
    marginBottom:    spacing[3],
    overflow:        'hidden',
    ...shadow.sm,
  },
  faqHeader: {
    flexDirection:  'row',
    justifyContent: 'space-between',
    alignItems:     'flex-start',
    padding:        spacing[4],
    gap:            spacing[3],
  },
  faqQ: {
    flex:       1,
    fontSize:   fontSize.base,
    fontWeight: '600',
    color:      colors.text,
    lineHeight: 20,
  },
  faqToggle: {
    fontSize:  22,
    color:     colors.primary,
    flexShrink: 0,
    lineHeight: 24,
  },
  faqToggleOpen: {
    transform: [{ rotate: '45deg' }],
  },
  faqBody: {
    paddingHorizontal: spacing[4],
    paddingBottom:     spacing[4],
    paddingTop:        spacing[2],
    borderTopWidth:    1,
    borderTopColor:    colors.border,
  },
  faqA: {
    fontSize:   fontSize.sm,
    color:      colors.text2,
    lineHeight: 20,
  },
  contactCard: {
    backgroundColor: colors.surface,
    borderRadius:    radius.lg,
    borderWidth:     1,
    borderColor:     colors.border,
    padding:         spacing[5],
    alignItems:      'center',
    gap:             spacing[3],
    marginTop:       spacing[6],
    ...shadow.sm,
  },
  contactIcon: {
    fontSize: 32,
    opacity:  0.6,
  },
  contactHeading: {
    fontSize:   fontSize.md,
    fontWeight: '700',
    color:      colors.text,
  },
  contactBody: {
    fontSize:  fontSize.sm,
    color:     colors.text2,
    textAlign: 'center',
    maxWidth:  240,
    lineHeight: 19,
  },
  btn: {
    paddingVertical:   spacing[3],
    paddingHorizontal: spacing[5],
    borderRadius:      radius.md,
    alignItems:        'center',
    minHeight:         44,
    justifyContent:    'center',
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
});
