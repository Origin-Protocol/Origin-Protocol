import { useState, FormEvent } from 'react';
import { useAuth } from '../hooks/useAuth';

export default function LoginScreen() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    <main style={{ maxWidth: 360, margin: '60px auto' }}>
      <h1 style={{ textAlign: 'center' }}>🎬 Origin Social</h1>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={() => setMode('login')} disabled={mode === 'login'}>Log in</button>
        <button onClick={() => setMode('register')} disabled={mode === 'register'}>Create account</button>
      </div>
      <form onSubmit={(e) => void handleSubmit(e)}>
        {mode === 'register' && (
          <>
            <div>
              <label>Username<br />
                <input value={username} onChange={(e) => setUsername(e.target.value)} required style={{ width: '100%' }} />
              </label>
            </div>
            <div>
              <label>Display name (optional)<br />
                <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} style={{ width: '100%' }} />
              </label>
            </div>
          </>
        )}
        <div>
          <label>Email<br />
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required style={{ width: '100%' }} />
          </label>
        </div>
        <div>
          <label>Password<br />
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required style={{ width: '100%' }} />
          </label>
        </div>
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <button type="submit" disabled={loading} style={{ width: '100%', marginTop: 8 }}>
          {loading ? '…' : mode === 'login' ? 'Log in' : 'Create account'}
        </button>
      </form>
    </main>
  );
}
