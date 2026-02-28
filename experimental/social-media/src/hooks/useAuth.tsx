import { createContext, useContext, useState, useCallback, ReactNode } from 'react';
import { User, AuthState } from '../types';
import { authApi } from '../api/client';

interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string, displayName?: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const token = localStorage.getItem('origin_token');
    const raw = localStorage.getItem('origin_user');
    const user: User | null = raw ? (JSON.parse(raw) as User) : null;
    return { token, user };
  });

  const login = useCallback(async (email: string, password: string) => {
    const { user, token } = await authApi.login({ email, password });
    localStorage.setItem('origin_token', token);
    localStorage.setItem('origin_user', JSON.stringify(user));
    setState({ user, token });
  }, []);

  const register = useCallback(async (username: string, email: string, password: string, displayName?: string) => {
    const { user, token } = await authApi.register({ username, email, password, displayName });
    localStorage.setItem('origin_token', token);
    localStorage.setItem('origin_user', JSON.stringify(user));
    setState({ user, token });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('origin_token');
    localStorage.removeItem('origin_user');
    setState({ user: null, token: null });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
