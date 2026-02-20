import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './hooks/useAuth';
import NavBar from './components/NavBar';
import FeedScreen from './screens/FeedScreen';
import UploadScreen from './screens/UploadScreen';
import ProfileScreen from './screens/ProfileScreen';
import LoginScreen from './screens/LoginScreen';

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div style={{ paddingBottom: 64 }}>
          <Routes>
            <Route path="/" element={<FeedScreen />} />
            <Route path="/upload" element={<UploadScreen />} />
            <Route path="/profile" element={<ProfileScreen />} />
            <Route path="/profile/:id" element={<ProfileScreen />} />
            <Route path="/login" element={<LoginScreen />} />
          </Routes>
        </div>
        <NavBar />
      </BrowserRouter>
    </AuthProvider>
  );
}
