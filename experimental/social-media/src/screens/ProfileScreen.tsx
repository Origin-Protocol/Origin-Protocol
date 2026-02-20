import { useEffect, useState } from 'react';
import { usersApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { User, VideoMeta } from '../types';
import VideoCard from '../components/VideoCard';

interface Props {
  userId?: string; // if omitted, shows the authenticated user's own profile
}

export default function ProfileScreen({ userId }: Props) {
  const { user: me, logout } = useAuth();
  const targetId = userId ?? me?.id;

  const [profile, setProfile] = useState<User | null>(null);
  const [videos, setVideos] = useState<VideoMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const isOwn = !userId || userId === me?.id;

  useEffect(() => {
    if (!targetId) { setLoading(false); return; }

    const fetchData = async () => {
      try {
        const profileData = await usersApi.getProfile(targetId);
        setProfile(profileData.user);
        // TODO: add a GET /api/users/:id/videos endpoint to list a creator's videos
        setVideos([]);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    };

    void fetchData();
  }, [targetId]);

  if (!targetId) return <p>Please <a href="/login">log in</a> to view your profile.</p>;
  if (loading) return <p>Loading…</p>;
  if (error) return <p style={{ color: 'red' }}>Error: {error}</p>;
  if (!profile) return <p>User not found.</p>;

  return (
    <main style={{ maxWidth: 480, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{ width: 64, height: 64, borderRadius: '50%', background: '#ddd', overflow: 'hidden' }}>
          {profile.avatarUrl
            ? <img src={profile.avatarUrl} alt="avatar" style={{ width: '100%' }} />
            : <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', fontSize: 28 }}>👤</span>
          }
        </div>
        <div>
          <h2 style={{ margin: 0 }}>{profile.displayName}</h2>
          <p style={{ margin: 0, color: '#666' }}>@{profile.username}</p>
          {profile.creatorKeyId && (
            <p style={{ margin: 0, fontSize: 12, color: 'green' }}>✅ Origin Protocol verified creator</p>
          )}
        </div>
      </div>
      {profile.bio && <p>{profile.bio}</p>}
      {isOwn && (
        <button onClick={logout} style={{ marginTop: 8 }}>Log out</button>
      )}
      <h3>Videos</h3>
      {videos.length === 0 && <p>No videos yet.</p>}
      {videos.map((v) => <VideoCard key={v.id} video={v} />)}
    </main>
  );
}
