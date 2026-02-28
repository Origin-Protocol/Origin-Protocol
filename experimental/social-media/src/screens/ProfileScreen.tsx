import { useEffect, useState, FormEvent } from 'react';
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
  const [videos, setVideos]   = useState<VideoMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving]   = useState(false);
  const [editName, setEditName] = useState('');
  const [editBio, setEditBio]   = useState('');

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

  function startEdit() {
    if (!profile) return;
    setEditName(profile.displayName);
    setEditBio(profile.bio ?? '');
    setEditing(true);
  }

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    try {
      const { user } = await usersApi.updateMe({
        displayName: editName.trim() || undefined,
        bio:         editBio.trim() || undefined,
      });
      setProfile(user);
      setEditing(false);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (!targetId) {
    return (
      <main className="page">
        <div className="empty-state" style={{ paddingTop: 'var(--sp-12)' }}>
          <span className="empty-state-icon">◎</span>
          <p>Please <a href="/login">log in</a> to view your profile.</p>
        </div>
      </main>
    );
  }

  if (loading) {
    return (
      <main className="page">
        {/* Avatar skeleton */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-4)', paddingTop: 'var(--sp-6)' }}>
          <div className="skeleton" style={{ width: 72, height: 72, borderRadius: '50%', flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <div className="skeleton" style={{ height: 18, width: '55%', marginBottom: 'var(--sp-2)' }} />
            <div className="skeleton" style={{ height: 13, width: '35%' }} />
          </div>
        </div>
        <hr className="divider" />
        <div className="skeleton" style={{ height: 160, borderRadius: 'var(--radius-lg)' }} />
      </main>
    );
  }

  if (error) {
    return (
      <main className="page">
        <div className="inline-error" style={{ marginTop: 'var(--sp-6)' }}>⚠ {error}</div>
      </main>
    );
  }

  if (!profile) {
    return (
      <main className="page">
        <div className="empty-state">
          <span className="empty-state-icon">◎</span>
          <p>User not found.</p>
        </div>
      </main>
    );
  }

  return (
    <main className="page">
      {/* Profile header */}
      <header style={{
        display:      'flex',
        alignItems:   'center',
        gap:          'var(--sp-4)',
        paddingTop:   'var(--sp-5)',
        paddingBottom:'var(--sp-5)',
      }}>
        {/* Avatar */}
        <div style={{
          width:        72,
          height:       72,
          borderRadius: '50%',
          background:   'var(--color-surface-2)',
          overflow:     'hidden',
          flexShrink:   0,
          border:       '2px solid var(--color-border)',
          display:      'flex',
          alignItems:   'center',
          justifyContent:'center',
          fontSize:     32,
        }}>
          {profile.avatarUrl
            ? <img src={profile.avatarUrl} alt="avatar" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            : '◎'
          }
        </div>

        {/* Name / username */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <h2 style={{
            fontSize:     20,
            fontWeight:   700,
            color:        'var(--color-text)',
            overflow:     'hidden',
            textOverflow: 'ellipsis',
            whiteSpace:   'nowrap',
          }}>
            {profile.displayName}
          </h2>
          <p style={{ fontSize: 14, color: 'var(--color-text-muted)', marginTop: 2 }}>
            @{profile.username}
          </p>
          {profile.creatorKeyId && (
            <span className="badge badge--success" style={{ marginTop: 'var(--sp-2)' }}>
              ✓ Origin Protocol verified
            </span>
          )}
        </div>
      </header>

      {/* Actions — own profile only */}
      {isOwn && !editing && (
        <div style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-5)' }}>
          <button
            className="btn btn--outline btn--sm"
            onClick={startEdit}
            style={{ flex: 1 }}
          >
            Edit profile
          </button>
          <button
            className="btn btn--ghost btn--sm"
            onClick={logout}
            style={{ flex: 1 }}
          >
            Log out
          </button>
        </div>
      )}

      {/* Inline edit form */}
      {isOwn && editing && (
        <div className="card" style={{ marginBottom: 'var(--sp-5)' }}>
          <div className="card-body">
            <p style={{ fontWeight: 700, fontSize: 15, marginBottom: 'var(--sp-4)', color: 'var(--color-text)' }}>
              Edit profile
            </p>
            <form onSubmit={(e) => void handleSave(e)}>
              <div className="field">
                <label className="field-label" htmlFor="prof-name">Display name</label>
                <input
                  id="prof-name"
                  className="input"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  placeholder="Your Name"
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="prof-bio">
                  Bio
                  <span className="optional"> (optional)</span>
                </label>
                <textarea
                  id="prof-bio"
                  className="textarea"
                  value={editBio}
                  onChange={(e) => setEditBio(e.target.value)}
                  placeholder="Tell people about yourself…"
                  rows={3}
                />
              </div>
              {error && <div className="inline-error" style={{ marginBottom: 'var(--sp-3)' }}>⚠ {error}</div>}
              <div style={{ display: 'flex', gap: 'var(--sp-3)' }}>
                <button type="button" className="btn btn--outline btn--sm" onClick={() => setEditing(false)} style={{ flex: 1 }}>
                  Cancel
                </button>
                <button type="submit" className="btn btn--primary btn--sm" disabled={saving} style={{ flex: 1 }}>
                  {saving ? '…' : 'Save'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Bio */}
      {profile.bio && (
        <p style={{
          fontSize:      14,
          color:         'var(--color-text-2)',
          lineHeight:    1.6,
          marginBottom:  'var(--sp-5)',
          padding:       'var(--sp-3) var(--sp-4)',
          background:    'var(--color-surface-2)',
          borderRadius:  'var(--radius-md)',
        }}>
          {profile.bio}
        </p>
      )}

      <hr className="divider" />

      {/* Videos section */}
      <h3 className="section-title">Videos</h3>
      {videos.length === 0 ? (
        <div className="empty-state">
          <span className="empty-state-icon">📹</span>
          <p>
            {isOwn
              ? "You haven't uploaded any videos yet."
              : 'No videos yet.'}
          </p>
          {isOwn && (
            <a className="btn btn--primary" href="/upload">Upload your first video</a>
          )}
        </div>
      ) : (
        videos.map((v) => <VideoCard key={v.id} video={v} />)
      )}
    </main>
  );
}
