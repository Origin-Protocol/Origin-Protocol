import { useState, FormEvent } from 'react';
import { useAuth } from '../hooks/useAuth';

export default function LoginScreen() {
  const { login, register } = useAuth();
  const [mode, setMode]             = useState<'login' | 'register'>('login');
  const [email, setEmail]           = useState('');
  const [password, setPassword]     = useState('');
  const [username, setUsername]     = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (mode === 'login') {
        await login(email, password);
      } else {
        await register(username, email, password, displayName || undefined);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={{
      minHeight:      '100dvh',
      display:        'flex',
      alignItems:     'center',
      justifyContent: 'center',
      padding:        'var(--sp-4)',
      background:     'var(--color-bg)',
    }}>
      <div style={{ width: '100%', maxWidth: 380 }}>
        {/* Brand header */}
        <div style={{ textAlign: 'center', marginBottom: 'var(--sp-8)' }}>
          <span style={{ fontSize: 44, lineHeight: 1 }}>⬡</span>
          <h1 style={{
            fontSize:      26,
            fontWeight:    800,
            letterSpacing: '-.5px',
            color:         'var(--color-text)',
            marginTop:     'var(--sp-2)',
          }}>
            Origin Social
          </h1>
          <p style={{ fontSize: 14, color: 'var(--color-text-muted)', marginTop: 'var(--sp-1)' }}>
            {mode === 'login' ? 'Sign in to your account' : 'Create your creator account'}
          </p>
        </div>

        {/* Card */}
        <div className="card">
          <div className="card-body">
            {/* Mode toggle */}
            <div style={{
              display:       'grid',
              gridTemplateColumns: '1fr 1fr',
              gap:           'var(--sp-2)',
              marginBottom:  'var(--sp-5)',
              background:    'var(--color-surface-2)',
              borderRadius:  'var(--radius-md)',
              padding:       'var(--sp-1)',
            }}>
              {(['login', 'register'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => { setMode(m); setError(null); }}
                  style={{
                    padding:      '8px',
                    borderRadius: 'var(--radius-sm)',
                    border:       'none',
                    fontSize:     13,
                    fontWeight:   600,
                    cursor:       'pointer',
                    transition:   'all var(--transition)',
                    background:   mode === m ? 'var(--color-surface)' : 'transparent',
                    color:        mode === m ? 'var(--color-primary)' : 'var(--color-text-muted)',
                    boxShadow:    mode === m ? 'var(--shadow-sm)' : 'none',
                  }}
                >
                  {m === 'login' ? 'Log in' : 'Create account'}
                </button>
              ))}
            </div>

            {/* Form */}
            <form onSubmit={(e) => void handleSubmit(e)}>
              {mode === 'register' && (
                <>
                  <div className="field">
                    <label className="field-label" htmlFor="login-username">Username</label>
                    <input
                      id="login-username"
                      className="input"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="your_handle"
                      autoComplete="username"
                      required
                    />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="login-display">
                      Display name
                      <span className="optional"> (optional)</span>
                    </label>
                    <input
                      id="login-display"
                      className="input"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      placeholder="Your Name"
                      autoComplete="name"
                    />
                  </div>
                </>
              )}

              <div className="field">
                <label className="field-label" htmlFor="login-email">Email</label>
                <input
                  id="login-email"
                  className="input"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="login-password">Password</label>
                <input
                  id="login-password"
                  className="input"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                  required
                />
              </div>

              {error && (
                <div className="inline-error" style={{ marginBottom: 'var(--sp-4)' }}>
                  ⚠ {error}
                </div>
              )}

              <button
                type="submit"
                className="btn btn--primary btn--full"
                disabled={loading}
              >
                {loading
                  ? <><span className="spinner" style={{ width: 16, height: 16 }} /> Signing in…</>
                  : mode === 'login' ? 'Log in' : 'Create account'
                }
              </button>
            </form>
          </div>
        </div>
      </div>
    </main>
  );
}
