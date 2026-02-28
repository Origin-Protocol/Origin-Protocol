import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './hooks/useAuth';
import { useAuth } from './hooks/useAuth';
import NavBar from './components/NavBar';
import FeedScreen from './screens/FeedScreen';
import UploadScreen from './screens/UploadScreen';
import ProfileScreen from './screens/ProfileScreen';
import LoginScreen from './screens/LoginScreen';
import LandingScreen from './screens/LandingScreen';
import HelpScreen from './screens/HelpScreen';
import VideoDetailScreen from './screens/VideoDetailScreen';

function RootPage() {
  const { user } = useAuth();
  return user ? <FeedScreen /> : <LandingScreen />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div>
          <Routes>
            <Route path="/"           element={<RootPage />} />
            <Route path="/upload"     element={<UploadScreen />} />
            <Route path="/profile"    element={<ProfileScreen />} />
            <Route path="/profile/:id" element={<ProfileScreen />} />
            <Route path="/login"      element={<LoginScreen />} />
            <Route path="/help"       element={<HelpScreen />} />
            <Route path="/video/:id"  element={<VideoDetailScreen />} />
          </Routes>
        </div>
        <NavBar />
      </BrowserRouter>
    </AuthProvider>
  );
}
