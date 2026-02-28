import type { ConversationMessage } from '../../types';
import type { User } from '../../types';

type Props = {
  message: ConversationMessage;
  mine: boolean;
  sender?: User | null;
  timestamp?: string;
  statusLabel?: string;
  showReadReceipt?: boolean;
  onReact?: (messageId: string, emoji: string) => void | Promise<void>;
};

export default function MessageBubble({ message, mine, sender, timestamp, statusLabel, showReadReceipt }: Props) {
  const senderName = sender?.displayName || sender?.username || message.senderId;
  return (
    <div style={{ display: 'grid', justifyItems: mine ? 'end' : 'start' }}>
      <div
        style={{
          maxWidth: '78%',
          border: '1px solid #1f2937',
          borderRadius: 10,
          background: mine ? '#1d4ed8' : '#0b1220',
          color: '#e5e7eb',
          padding: '8px 10px',
        }}
      >
        <p style={{ margin: 0, fontSize: 11, opacity: 0.8 }}>{senderName}</p>
        <p style={{ margin: '3px 0 0' }}>{message.content}</p>
        <p style={{ margin: '4px 0 0', fontSize: 10, opacity: 0.8 }}>
          {timestamp || ''}{showReadReceipt && statusLabel ? ` • ${statusLabel}` : ''}
        </p>
      </div>
    </div>
  );
}
