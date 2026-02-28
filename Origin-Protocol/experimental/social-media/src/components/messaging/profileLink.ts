import type { User } from '../../types';

export function profileHref(user: User): string {
  return user.username ? `/u/${encodeURIComponent(user.username)}` : `/creator/${user.id}`;
}

export function userInitials(user: User): string {
  const source = (user.displayName || user.username || '').trim();
  if (!source) return 'U';
  const parts = source.split(/\s+/).slice(0, 2);
  return parts.map((part) => part[0]?.toUpperCase() ?? '').join('') || 'U';
}
