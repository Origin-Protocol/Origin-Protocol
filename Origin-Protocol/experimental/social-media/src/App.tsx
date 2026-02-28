import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ReactElement } from 'react';
import { AuthProvider } from './hooks/useAuth';
import { useAuth } from './hooks/useAuth';
import NavBar from './components/NavBar';
import FeedScreen from './screens/FeedScreen';
import UploadScreen from './screens/UploadScreen';
import MeSettingsScreen from './screens/MeSettingsScreen';
import LoginScreen from './screens/LoginScreen';
import VerificationScreen from './screens/VerificationScreen';
import CreatorPageScreen from './screens/CreatorPageScreen';
import LandingScreen from './screens/LandingScreen';
import HelpScreen from './screens/HelpScreen';
import BillingScreen from './screens/BillingScreen';
import AdminDashboardScreen from './screens/AdminDashboardScreen';
import TermsScreen from './screens/TermsScreen';
import MessagingScreen from './screens/MessagingScreen';
import NotificationsScreen from './screens/NotificationsScreen';
import VideoDetailScreen from './screens/VideoDetailScreen';
import LiveScreen from './screens/LiveScreen';
import AbigailScreen from './screens/AbigailScreen';

function RequireAuth({ children }: { children: ReactElement }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function RootRoute() {
  const { user } = useAuth();
  return user ? <FeedScreen /> : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div style={{ paddingBottom: 72, minHeight: '100vh', background: 'radial-gradient(circle at top, #1f2937 0%, #020617 55%)' }}>
          <Routes>
            <Route path="/" element={<RootRoute />} />
            <Route path="/feed" element={<RequireAuth><FeedScreen /></RequireAuth>} />
            <Route path="/landing" element={<RequireAuth><LandingScreen /></RequireAuth>} />
            <Route path="/upload" element={<RequireAuth><UploadScreen /></RequireAuth>} />
            <Route path="/profile" element={<RequireAuth><MeSettingsScreen /></RequireAuth>} />
            <Route path="/profile/:id" element={<RequireAuth><CreatorPageScreen /></RequireAuth>} />
            <Route path="/u/:username" element={<RequireAuth><CreatorPageScreen /></RequireAuth>} />
            <Route path="/login" element={<LoginScreen />} />
            <Route path="/terms" element={<TermsScreen />} />
            <Route path="/verify/:id" element={<RequireAuth><VerificationScreen /></RequireAuth>} />
            <Route path="/creator/:id" element={<RequireAuth><CreatorPageScreen /></RequireAuth>} />
            <Route path="/help" element={<RequireAuth><HelpScreen /></RequireAuth>} />
            <Route path="/billing" element={<RequireAuth><BillingScreen /></RequireAuth>} />
            <Route path="/studio" element={<RequireAuth><AbigailScreen /></RequireAuth>} />
            <Route path="/dashboard" element={<RequireAuth><MeSettingsScreen /></RequireAuth>} />
            <Route path="/live" element={<RequireAuth><LiveScreen /></RequireAuth>} />
            <Route path="/live/:sessionId" element={<RequireAuth><LiveScreen /></RequireAuth>} />
            <Route path="/abigail" element={<RequireAuth><AbigailScreen /></RequireAuth>} />
            <Route path="/messages" element={<RequireAuth><MessagingScreen /></RequireAuth>} />
            <Route path="/notifications" element={<RequireAuth><NotificationsScreen /></RequireAuth>} />
            <Route path="/video/:id" element={<RequireAuth><VideoDetailScreen /></RequireAuth>} />
            <Route path="/admin" element={<RequireAuth><AdminDashboardScreen /></RequireAuth>} />
          </Routes>
        </div>
        <NavBar />
      </BrowserRouter>
    </AuthProvider>
  );
}
