import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

const FEATURES = [
  {
    icon: '🔐',
    title: 'Verified ownership',
    body: 'Every video carries a cryptographic Origin Protocol proof, so viewers always know who created it.',
  },
  {
    icon: '🎬',
    title: 'Authentic creator content',
    body: 'Only verified creators can upload. No deepfakes, no impersonators — just real, authenticated work.',
  },
  {
    icon: '🌐',
    title: 'Open creator tools',
    body: 'Upload, share, and reach your audience on open, transparent infrastructure.',
  },
];

export default function LandingScreen() {
  const { user } = useAuth();
  // useNavigate is not needed — RootPage handles the auth-based routing
  if (user) return null;

  return (
    <main style={{
      maxWidth: 'var(--content-max)',
      margin:   '0 auto',
      padding:  'var(--sp-4)',
      paddingBottom: 120,
    }}>
      {/* Hero */}
      <div style={{ textAlign: 'center', paddingTop: 'var(--sp-12)', paddingBottom: 'var(--sp-10)' }}>
        <span style={{ fontSize: 52, display: 'block', marginBottom: 'var(--sp-3)', color: 'var(--color-primary)' }}>⬡</span>
        <h1 style={{
          fontSize:      32,
          fontWeight:    800,
          letterSpacing: -0.6,
          color:         'var(--color-text)',
          marginBottom:  'var(--sp-3)',
          lineHeight:    1.2,
        }}>
          Origin Social
        </h1>
        <p style={{
          fontSize:   17,
          color:      'var(--color-text-2)',
          maxWidth:   360,
          margin:     '0 auto',
          lineHeight: 1.6,
        }}>
          A creator platform where every video carries provable, on-chain ownership via Origin Protocol.
        </p>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', justifyContent: 'center', marginTop: 'var(--sp-8)' }}>
          <Link to="/login?register=1" className="btn btn--primary" style={{ minWidth: 160, borderRadius: 'var(--radius-full)' }}>
            Get started free
          </Link>
          <Link to="/login" className="btn btn--outline" style={{ minWidth: 120, borderRadius: 'var(--radius-full)' }}>
            Log in
          </Link>
        </div>
      </div>

      {/* Features */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
        {FEATURES.map((f) => (
          <div key={f.title} className="card">
            <div className="card-body" style={{ display: 'flex', gap: 'var(--sp-4)', alignItems: 'flex-start' }}>
              <span style={{ fontSize: 28, flexShrink: 0, lineHeight: 1.2 }}>{f.icon}</span>
              <div>
                <p style={{ fontWeight: 700, fontSize: 15, color: 'var(--color-text)', marginBottom: 4 }}>{f.title}</p>
                <p style={{ fontSize: 13, color: 'var(--color-text-2)', lineHeight: 1.65 }}>{f.body}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Footer note */}
      <p style={{ textAlign: 'center', fontSize: 13, color: 'var(--color-text-muted)', marginTop: 'var(--sp-10)' }}>
        Already a creator?{' '}
        <Link to="/login">Sign in to your account →</Link>
      </p>
    </main>
  );
}
