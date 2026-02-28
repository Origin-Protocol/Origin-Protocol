import type { Conversation, User } from '../../types';

type Props = {
  conversation: Conversation;
  title: string;
  subtitle: string;
  active: boolean;
  unreadCount: number;
  timestamp: string;
  relationship: 'friend' | 'subscriber' | 'creator' | 'group';
  counterparty?: User | null;
  onClick?: () => void;
  onSelect?: () => void;
};

export default function ConversationSidebarItem({ title, subtitle, active, unreadCount, timestamp, relationship, onClick, onSelect }: Props) {
  const clickHandler = onSelect ?? onClick ?? (() => undefined);
  return (
    <button
      type="button"
      onClick={clickHandler}
      style={{
        textAlign: 'left',
        border: '1px solid #1f2937',
        borderRadius: 10,
        background: active ? '#111827' : '#0b1220',
        color: '#e5e7eb',
        padding: '8px 10px',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
        <strong style={{ fontSize: 13 }}>{title}</strong>
        {unreadCount > 0 ? <span style={{ fontSize: 11, color: '#93c5fd' }}>{unreadCount}</span> : null}
      </div>
      <p style={{ margin: '4px 0 0', color: '#94a3b8', fontSize: 12 }}>{subtitle}</p>
      <p style={{ margin: '4px 0 0', color: '#64748b', fontSize: 11 }}>{relationship} • {timestamp}</p>
    </button>
  );
}
