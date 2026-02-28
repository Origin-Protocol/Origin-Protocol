import { useState, useRef, FormEvent, DragEvent } from 'react';
import { videosApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { VideoMeta } from '../types';

export default function UploadScreen() {
  const { user } = useAuth();
  const fileRef  = useRef<HTMLInputElement>(null);

  const [title, setTitle]           = useState('');
  const [description, setDescription] = useState('');
  const [bundleId, setBundleId]     = useState('');
  const [uploading, setUploading]   = useState(false);
  const [result, setResult]         = useState<VideoMeta | null>(null);
  const [error, setError]           = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragging, setDragging]     = useState(false);

  if (!user) {
    return (
      <main className="page">
        <div className="empty-state" style={{ paddingTop: 'var(--sp-12)' }}>
          <span className="empty-state-icon">⊕</span>
          <p>Please <a href="/login">log in</a> to upload videos.</p>
        </div>
      </main>
    );
  }

  function pickFile(file: File) {
    setSelectedFile(file);
    setError(null);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) pickFile(file);
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const file = selectedFile ?? fileRef.current?.files?.[0];
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

  /* ── Success state ─────────────────────────────────────────────────────── */
  if (result) {
    return (
      <main className="page">
        <div style={{ textAlign: 'center', paddingTop: 'var(--sp-8)', paddingBottom: 'var(--sp-8)' }}>
          <div style={{
            width:          72,
            height:         72,
            borderRadius:   '50%',
            background:     'var(--color-success-s)',
            display:        'flex',
            alignItems:     'center',
            justifyContent: 'center',
            fontSize:       32,
            margin:         '0 auto var(--sp-4)',
          }}>
            ✓
          </div>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text)', marginBottom: 'var(--sp-2)' }}>
            Upload successful!
          </h2>
          <p style={{ fontSize: 15, color: 'var(--color-text-muted)', marginBottom: 'var(--sp-5)' }}>
            {result.title}
          </p>
          {result.originVerified && (
            <span className="badge badge--success" style={{ marginBottom: 'var(--sp-5)' }}>
              ✓ Origin Protocol ownership verified
            </span>
          )}
        </div>

        <video
          src={result.videoUrl}
          controls
          className="card"
          style={{ width: '100%', marginBottom: 'var(--sp-5)' }}
        />

        <button
          className="btn btn--outline btn--full"
          onClick={() => { setResult(null); setSelectedFile(null); setTitle(''); setDescription(''); setBundleId(''); }}
        >
          Upload another video
        </button>
      </main>
    );
  }

  /* ── Upload form ───────────────────────────────────────────────────────── */
  return (
    <main className="page">
      <header style={{ paddingTop: 'var(--sp-5)', marginBottom: 'var(--sp-6)' }}>
        <h1 className="page-title">Upload a video</h1>
        <p className="page-lead">Share your authenticated content with the Origin Social community.</p>
      </header>

      <form onSubmit={(e) => void handleSubmit(e)}>
        {/* Drop zone */}
        <div
          onDragEnter={() => setDragging(true)}
          onDragLeave={() => setDragging(false)}
          onDragOver={(e) => e.preventDefault()}
          onDrop={onDrop}
          onClick={() => fileRef.current?.click()}
          style={{
            border:         `2px dashed ${dragging ? 'var(--color-primary)' : 'var(--color-border)'}`,
            borderRadius:   'var(--radius-lg)',
            background:     dragging ? 'var(--color-primary-s)' : 'var(--color-surface)',
            padding:        'var(--sp-8) var(--sp-4)',
            textAlign:      'center',
            cursor:         'pointer',
            marginBottom:   'var(--sp-5)',
            transition:     'all var(--transition)',
          }}
        >
          <input
            ref={fileRef}
            type="file"
            accept="video/*"
            style={{ display: 'none' }}
            onChange={(e) => { const f = e.target.files?.[0]; if (f) pickFile(f); }}
          />
          <span style={{ fontSize: 36, lineHeight: 1, display: 'block', marginBottom: 'var(--sp-3)' }}>⊕</span>
          {selectedFile ? (
            <>
              <p style={{ fontWeight: 600, color: 'var(--color-text)', fontSize: 15 }}>{selectedFile.name}</p>
              <p style={{ fontSize: 13, color: 'var(--color-text-muted)', marginTop: 'var(--sp-1)' }}>
                {(selectedFile.size / 1024 / 1024).toFixed(1)} MB · Click to change
              </p>
            </>
          ) : (
            <>
              <p style={{ fontWeight: 600, color: 'var(--color-text)', fontSize: 15 }}>
                Drop your video here
              </p>
              <p style={{ fontSize: 13, color: 'var(--color-text-muted)', marginTop: 'var(--sp-1)' }}>
                or click to browse
              </p>
            </>
          )}
        </div>

        {/* Title */}
        <div className="field">
          <label className="field-label" htmlFor="upload-title">Title</label>
          <input
            id="upload-title"
            className="input"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Give your video a title"
            maxLength={150}
            required
          />
        </div>

        {/* Description */}
        <div className="field">
          <label className="field-label" htmlFor="upload-desc">
            Description
            <span className="optional"> (optional)</span>
          </label>
          <textarea
            id="upload-desc"
            className="textarea"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Tell viewers about your video…"
            maxLength={500}
            rows={3}
          />
        </div>

        {/* Origin Bundle ID */}
        <div className="field">
          <label className="field-label" htmlFor="upload-bundle">
            Origin Bundle ID
            <span className="optional"> (optional)</span>
          </label>
          <input
            id="upload-bundle"
            className="input"
            value={bundleId}
            onChange={(e) => setBundleId(e.target.value)}
            placeholder="Links this video to your Origin Protocol ownership proof"
            style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}
          />
          <span style={{ fontSize: 12, color: 'var(--color-text-muted)' }}>
            Provide your Origin bundle ID to attach a verified ownership proof to this upload.
          </span>
        </div>

        {error && (
          <div className="inline-error" style={{ marginBottom: 'var(--sp-4)' }}>
            ⚠ {error}
          </div>
        )}

        <button
          type="submit"
          className="btn btn--primary btn--full"
          disabled={uploading}
        >
          {uploading
            ? <><span className="spinner" style={{ width: 16, height: 16 }} /> Uploading…</>
            : 'Upload video'
          }
        </button>
      </form>
    </main>
  );
}
