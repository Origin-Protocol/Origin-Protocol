import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

export default function NavBar() {
  const { user } = useAuth();
  const { pathname } = useLocation();

  const active = (path: string) =>
    pathname === path ? { fontWeight: 'bold' as const } : {};

  return (
    <nav style={{
      position: 'fixed', bottom: 0, left: 0, right: 0,
      display: 'flex', justifyContent: 'space-around',
      padding: '8px 0', background: '#fff', borderTop: '1px solid #eee',
      zIndex: 100,
    }}>
      <Link to="/" style={active('/')}>🏠 Feed</Link>
      <Link to="/upload" style={active('/upload')}>➕ Upload</Link>
      <Link to={user ? '/profile' : '/login'} style={active('/profile')}>👤 Me</Link>
    </nav>
  );
}
