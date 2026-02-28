import { useState } from 'react';
import { Link } from 'react-router-dom';

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
    a: 'Go to your profile, tap "Edit profile", and add your Origin Bundle ID. The platform checks your key status via the ledger API and marks your account as verified. Full documentation is at origin.network/docs.',
  },
  {
    q: 'How do I upload a video?',
    a: 'Tap the Upload tab in the bottom navigation bar. Select a video file, add a title and optional description, then press Upload. If your account is Origin-verified, the video will automatically carry an ownership proof badge.',
  },
  {
    q: 'Can I delete a video I uploaded?',
    a: 'Yes. Open the video page and use the options menu to delete it. Note that the on-chain ownership proof remains on the ledger — only the hosted media file is removed.',
  },
  {
    q: 'Are my videos public?',
    a: 'All uploaded videos are public on Origin Social. Private and unlisted video options are on the roadmap.',
  },
  {
    q: 'How do I report inappropriate content?',
    a: 'Use the options menu on any video to flag it for review. Our moderation team reviews reports within 24 hours.',
  },
  {
    q: 'How do I contact support?',
    a: 'Email support@origin.network or visit origin.network/support. We aim to respond within one business day.',
  },
];

function FaqItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="card" style={{ marginBottom: 'var(--sp-3)' }}>
      <button
        onClick={() => setOpen((v) => !v)}
        style={{
          width:          '100%',
          display:        'flex',
          justifyContent: 'space-between',
          alignItems:     'center',
          padding:        'var(--sp-4)',
          background:     'none',
          border:         'none',
          fontWeight:     600,
          fontSize:       14,
          color:          'var(--color-text)',
          textAlign:      'left',
          gap:            'var(--sp-3)',
          cursor:         'pointer',
        }}
        aria-expanded={open}
      >
        {q}
        <span style={{
          fontSize:   22,
          color:      'var(--color-primary)',
          flexShrink: 0,
          transition: 'transform .2s',
          transform:  open ? 'rotate(45deg)' : 'none',
          lineHeight: 1,
        }}>
          +
        </span>
      </button>
      {open && (
        <div style={{
          padding:    '0 var(--sp-4) var(--sp-4)',
          fontSize:   14,
          color:      'var(--color-text-2)',
          lineHeight: 1.7,
          borderTop:  '1px solid var(--color-border)',
          paddingTop: 'var(--sp-3)',
          marginTop:  0,
        }}>
          {a}
        </div>
      )}
    </div>
  );
}

export default function HelpScreen() {
  return (
    <main className="page">
      {/* Back */}
      <Link
        to="/"
        style={{
          display:        'inline-flex',
          alignItems:     'center',
          gap:            4,
          fontSize:       13,
          color:          'var(--color-text-muted)',
          textDecoration: 'none',
          marginTop:      'var(--sp-4)',
          marginBottom:   'var(--sp-5)',
        }}
      >
        ← Back
      </Link>

      <h1 className="page-title">Help & Support</h1>
      <p className="page-lead" style={{ marginBottom: 'var(--sp-6)' }}>
        Frequently asked questions and guides for Origin Social.
      </p>

      <h2 className="section-title">Frequently asked questions</h2>

      {FAQS.map((f) => <FaqItem key={f.q} q={f.q} a={f.a} />)}

      {/* Contact card */}
      <div className="card" style={{ marginTop: 'var(--sp-6)', textAlign: 'center' }}>
        <div className="card-body" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--sp-3)' }}>
          <span style={{ fontSize: 32, opacity: .6 }}>✉</span>
          <p style={{ fontWeight: 700, fontSize: 15, color: 'var(--color-text)' }}>Still need help?</p>
          <p style={{ fontSize: 13, color: 'var(--color-text-2)', maxWidth: 280, lineHeight: 1.6 }}>
            Reach the Origin Social team at{' '}
            <a href="mailto:support@origin.network">support@origin.network</a>.
          </p>
          <a
            className="btn btn--outline btn--sm"
            href="https://origin.network/docs"
            target="_blank"
            rel="noopener noreferrer"
          >
            View full documentation
          </a>
        </div>
      </div>
    </main>
  );
}
