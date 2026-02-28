import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useState } from 'react';

export default function LoginScreen() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  return (
    <main style={{ maxWidth: 520, margin: '40px auto', color: '#e5e7eb', padding: 12 }}>
      <h2 style={{ marginTop: 0 }}>Sign in</h2>
      <div style={{ display: 'grid', gap: 8 }}>
        <input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="Email" type="email" />
        <input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" type="password" />
      </div>
      <button
        type="button"
        onClick={async () => {
          try {
            setError(null);
            await login(email, password);
            navigate('/feed');
          } catch (err) {
            setError((err as Error).message || 'Unable to sign in');
          }
        }}
      >
        Continue
      </button>
      {error ? <p style={{ color: '#fca5a5' }}>{error}</p> : null}
    </main>
  );
}
