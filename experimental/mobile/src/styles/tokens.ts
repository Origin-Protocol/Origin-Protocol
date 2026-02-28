/**
 * Origin Social — Mobile Design Tokens
 * Mirrors the web design-system colour palette, spacing, and radius
 * so both apps stay visually consistent.
 */

export const colors = {
  primary:     '#6366F1',
  primaryDark: '#4F46E5',
  primarySoft: '#EEF2FF',

  bg:       '#F8FAFC',
  surface:  '#FFFFFF',
  surface2: '#F1F5F9',

  border:  '#E2E8F0',
  border2: '#CBD5E1',

  text:  '#1E293B',
  text2: '#475569',
  muted: '#94A3B8',

  success:     '#10B981',
  successSoft: '#ECFDF5',
  error:       '#EF4444',
  errorSoft:   '#FEF2F2',
  warning:     '#F59E0B',
} as const;

export const spacing = {
  1: 4,
  2: 8,
  3: 12,
  4: 16,
  5: 20,
  6: 24,
  8: 32,
  10: 40,
  12: 48,
} as const;

export const radius = {
  sm:   6,
  md:   10,
  lg:   14,
  xl:   20,
  full: 999,
} as const;

export const fontSize = {
  xs:   11,
  sm:   13,
  base: 14,
  md:   15,
  lg:   17,
  xl:   20,
  '2xl': 24,
  '3xl': 28,
} as const;

export const shadow = {
  sm: {
    shadowColor:   '#000',
    shadowOffset:  { width: 0, height: 1 },
    shadowOpacity: 0.07,
    shadowRadius:  3,
    elevation:     2,
  },
  md: {
    shadowColor:   '#000',
    shadowOffset:  { width: 0, height: 4 },
    shadowOpacity: 0.08,
    shadowRadius:  8,
    elevation:     4,
  },
} as const;
