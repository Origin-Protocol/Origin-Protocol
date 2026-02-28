import { createContext, useContext, useState, useCallback, ReactNode, useEffect } from 'react';
import { User, AuthState } from '../types';
import { authApi } from '../api/client';

interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  register: (
    username: string,
    email: string,
    password: string,
    displayName: string | undefined,
    acceptTerms: true,
    subscribeToProtection?: boolean,
  ) => Promise<{ subscribeToProtection: boolean }>;
  setUser: (user: User) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function readAuthStateFromStorage(): AuthState {
  if (typeof window === 'undefined') {
    return { token: null, user: null };
  }

  const token = window.localStorage.getItem('origin_token');
  const raw = window.localStorage.getItem('origin_user');
  if (!raw) return { token, user: null };

  try {
    const user = JSON.parse(raw) as User;
    return { token, user };
  } catch {
    window.localStorage.removeItem('origin_user');
    return { token, user: null };
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => readAuthStateFromStorage());

  useEffect(() => {
    const onStorage = () => {
      setState(readAuthStateFromStorage());
    };
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener('storage', onStorage);
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const { user, token } = await authApi.login({ email, password });
    window.localStorage.setItem('origin_token', token);
    window.localStorage.setItem('origin_user', JSON.stringify(user));
    setState({ user, token });
  }, []);

  const register = useCallback(async (
    username: string,
    email: string,
    password: string,
    displayName: string | undefined,
    acceptTerms: true,
    subscribeToProtection?: boolean,
  ) => {
    const { user, token, onboarding } = await authApi.register({
      username,
      email,
      password,
      displayName,
      acceptTerms,
      subscribeToProtection,
    });
    window.localStorage.setItem('origin_token', token);
    window.localStorage.setItem('origin_user', JSON.stringify(user));
    setState({ user, token });
    return { subscribeToProtection: Boolean(onboarding?.subscribeToProtection) };
  }, []);

  const setUser = useCallback((user: User) => {
    window.localStorage.setItem('origin_user', JSON.stringify(user));
    setState((prev) => ({ ...prev, user }));
  }, []);

  const logout = useCallback(() => {
    window.localStorage.removeItem('origin_token');
    window.localStorage.removeItem('origin_user');
    setState({ user: null, token: null });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, register, setUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
