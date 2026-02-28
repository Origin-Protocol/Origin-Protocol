import { Link } from 'react-router-dom';
import type { User } from '../../types';
import { profileHref, userInitials } from './profileLink';

type Props = {
  conversationId: string;
  title: string;
  snippet: string;
  unreadCount: number;
  timestamp: string;
  counterparty?: User | null;
  onNavigate: () => void;
};

export default function RecentConversationRow({
  conversationId,
  title,
  snippet,
  unreadCount,
  timestamp,
  counterparty,
  onNavigate,
}: Props) {
  return (
    <div
      style={{
        border: '1px solid #1f2937',
        borderRadius: 8,
        background: unreadCount > 0 ? '#111827' : '#0b1220',
        padding: '7px 8px',
        color: '#e5e7eb',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      }}
    >
      {counterparty ? (
        <Link
          to={profileHref(counterparty)}
          onClick={(event) => {
            event.stopPropagation();
            onNavigate();
          }}
          style={{ textDecoration: 'none' }}
        >
          <div style={{ width: 30, height: 30, borderRadius: '50%', overflow: 'hidden', border: '1px solid #334155', background: '#0f172a' }}>
            {counterparty.avatarUrl ? (
              <img src={counterparty.avatarUrl} alt={counterparty.displayName} style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            ) : (
              <span style={{ display: 'flex', width: '100%', height: '100%', alignItems: 'center', justifyContent: 'center', fontSize: 10, color: '#e2e8f0', fontWeight: 700 }}>
                {userInitials(counterparty)}
              </span>
            )}
          </div>
        </Link>
      ) : null}

      <Link
        to={`/messages?conversationId=${encodeURIComponent(conversationId)}`}
        onClick={onNavigate}
        style={{ minWidth: 0, flex: 1, textDecoration: 'none', color: '#e5e7eb' }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 6 }}>
          <strong style={{ fontSize: 12, fontWeight: unreadCount > 0 ? 800 : 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</strong>
          <span style={{ fontSize: 10, color: '#94a3b8', whiteSpace: 'nowrap' }}>{timestamp}</span>
        </div>
        <p style={{ margin: '3px 0 0', fontSize: 11, color: '#94a3b8', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontWeight: unreadCount > 0 ? 700 : 400 }}>
          {snippet}
        </p>
      </Link>

      {unreadCount > 0 ? <span style={{ minWidth: 18, borderRadius: 999, background: '#2563eb', color: '#fff', fontSize: 10, textAlign: 'center', padding: '1px 5px', fontWeight: 700 }}>{unreadCount > 99 ? '99+' : unreadCount}</span> : null}
    </div>
  );
}
