import { useState, useRef, FormEvent } from 'react';
import { videosApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { VideoMeta } from '../types';

export default function UploadScreen() {
  const { user } = useAuth();
  const fileRef = useRef<HTMLInputElement>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [bundleId, setBundleId] = useState('');
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<VideoMeta | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!user) {
    return <p>Please <a href="/login">log in</a> to upload videos.</p>;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) { setError('Please select a video file.'); return; }
    if (!title.trim()) { setError('Title is required.'); return; }

    const fd = new FormData();
    fd.append('video', file);
    fd.append('title', title.trim());
    if (description.trim()) fd.append('description', description.trim());
    if (bundleId.trim()) fd.append('originBundleId', bundleId.trim());

    setUploading(true);
    setError(null);
    try {
      const { video } = await videosApi.upload(fd);
      setResult(video);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUploading(false);
    }
  }

  if (result) {
    return (
      <div style={{ maxWidth: 480, margin: '0 auto' }}>
        <h2>Upload successful!</h2>
        <p><strong>{result.title}</strong></p>
        {result.originVerified && (
          <p style={{ color: 'green' }}>✅ Origin Protocol ownership verified</p>
        )}
        <video src={result.videoUrl} controls style={{ width: '100%' }} />
        <button onClick={() => setResult(null)}>Upload another</button>
      </div>
    );
  }

  return (
    <main style={{ maxWidth: 480, margin: '0 auto' }}>
      <h2>Upload a video</h2>
      <form onSubmit={(e) => void handleSubmit(e)}>
        <div>
          <label>Video file<br />
            <input ref={fileRef} type="file" accept="video/*" required />
          </label>
        </div>
        <div>
          <label>Title<br />
            <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={150} required style={{ width: '100%' }} />
          </label>
        </div>
        <div>
          <label>Description<br />
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} rows={3} style={{ width: '100%' }} />
          </label>
        </div>
        <div>
          <label>
            Origin Bundle ID <span style={{ fontSize: 12, color: '#888' }}>(optional — links this video to your Origin Protocol ownership proof)</span><br />
            <input value={bundleId} onChange={(e) => setBundleId(e.target.value)} style={{ width: '100%' }} />
          </label>
        </div>
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <button type="submit" disabled={uploading}>
          {uploading ? 'Uploading…' : 'Upload'}
        </button>
      </form>
    </main>
  );
}
