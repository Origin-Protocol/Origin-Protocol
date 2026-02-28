import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

interface NavItem {
  to: string;
  icon: string;
  label: string;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/',        icon: '⊞',  label: 'Feed'    },
  { to: '/upload',  icon: '⊕',  label: 'Upload'  },
  { to: '/profile', icon: '◎',  label: 'Profile' },
];

export default function NavBar() {
  const { user } = useAuth();
  const { pathname } = useLocation();

  return (
    <nav style={{
      position:       'fixed',
      bottom:         0,
      left:           0,
      right:          0,
      height:         'var(--nav-h)',
      background:     'var(--color-surface)',
      borderTop:      '1px solid var(--color-border)',
      display:        'flex',
      alignItems:     'stretch',
      zIndex:         200,
      boxShadow:      '0 -4px 12px rgba(0,0,0,.06)',
    }}>
      {NAV_ITEMS.map(({ to, icon, label }) => {
        const href = to === '/profile' ? (user ? '/profile' : '/login') : to;
        const isActive = pathname === href || (to === '/profile' && pathname.startsWith('/profile'));

        return (
          <Link
            key={to}
            to={href}
            style={{
              flex:            1,
              display:         'flex',
              flexDirection:   'column',
              alignItems:      'center',
              justifyContent:  'center',
              gap:             4,
              color:           isActive ? 'var(--color-primary)' : 'var(--color-text-muted)',
              textDecoration:  'none',
              fontSize:        11,
              fontWeight:      isActive ? 700 : 500,
              letterSpacing:   '.2px',
              transition:      'color var(--transition)',
              position:        'relative',
            }}
          >
            {isActive && (
              <span style={{
                position:    'absolute',
                top:         0,
                left:        '25%',
                right:       '25%',
                height:      3,
                background:  'var(--color-primary)',
                borderRadius: '0 0 var(--radius-sm) var(--radius-sm)',
              }} />
            )}
            <span style={{ fontSize: 20, lineHeight: 1 }}>{icon}</span>
            <span>{label}</span>
          </Link>
        );
      })}
    </nav>
  );
}
