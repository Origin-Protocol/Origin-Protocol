import { useEffect, useState } from 'react';

type Option = {
  label: string;
  value: string;
};

type Props = {
  label: string;
  value: string;
  placeholder?: string;
  type?: 'text' | 'email' | 'date' | 'tel' | 'url' | 'textarea' | 'select';
  options?: Option[];
  privateLabel?: boolean;
  onSave: (nextValue: string) => Promise<void> | void;
};

export default function EditableFieldRow({
  label,
  value,
  placeholder,
  type = 'text',
  options,
  privateLabel,
  onSave,
}: Props) {
  const [draft, setDraft] = useState(value);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDraft(value);
  }, [value]);

  async function handleSave(nextRaw: string) {
    const nextValue = nextRaw.trim();
    const priorValue = value.trim();
    if (nextValue === priorValue) {
      setError(null);
      return;
    }

    setSaving(true);
    setError(null);
    try {
      await onSave(nextValue);
    } catch (err) {
      setError((err as Error).message || 'Save failed');
    } finally {
      setSaving(false);
    }
  }

  function renderInput() {
    if (type === 'textarea') {
      return (
        <textarea
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={() => void handleSave(draft)}
          rows={3}
          placeholder={placeholder}
          style={{ width: '100%', border: '1px solid #334155', borderRadius: 8, background: '#020617', color: '#e5e7eb', padding: '8px 10px' }}
        />
      );
    }

    if (type === 'select') {
      return (
        <select
          value={draft}
          onChange={(event) => {
            const next = event.target.value;
            setDraft(next);
            void handleSave(next);
          }}
          style={{ width: '100%', border: '1px solid #334155', borderRadius: 8, background: '#020617', color: '#e5e7eb', padding: '8px 10px' }}
        >
          {(options ?? []).map((item) => (
            <option key={item.value} value={item.value}>{item.label}</option>
          ))}
        </select>
      );
    }

    return (
      <input
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        onBlur={() => void handleSave(draft)}
        onKeyDown={(event) => {
          if (event.key === 'Enter') {
            event.currentTarget.blur();
          }
        }}
        type={type}
        placeholder={placeholder}
        style={{ width: '100%', border: '1px solid #334155', borderRadius: 8, background: '#020617', color: '#e5e7eb', padding: '8px 10px' }}
      />
    );
  }

  return (
    <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
        <strong>{label}</strong>
        {privateLabel ? <span style={{ color: '#94a3b8', fontSize: 12 }}>private</span> : null}
      </div>

      <div style={{ display: 'grid', gap: 8 }}>
        {renderInput()}
        {saving ? <p style={{ margin: 0, color: '#93c5fd', fontSize: 12 }}>Saving…</p> : null}
        {error ? <p style={{ margin: 0, color: '#fca5a5', fontSize: 12 }}>{error}</p> : null}
      </div>
    </div>
  );
}
