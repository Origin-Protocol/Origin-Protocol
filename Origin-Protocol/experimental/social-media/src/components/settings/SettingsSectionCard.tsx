import { ReactNode } from 'react';

type Props = {
  title: string;
  description?: string;
  children: ReactNode;
};

export default function SettingsSectionCard({ title, description, children }: Props) {
  return (
    <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 12 }}>
      <div>
        <h3 style={{ margin: 0 }}>{title}</h3>
        {description ? <p style={{ margin: '4px 0 0', color: '#94a3b8', fontSize: 12 }}>{description}</p> : null}
      </div>
      <div style={{ marginTop: 12, display: 'grid', gap: 10 }}>{children}</div>
    </section>
  );
}
