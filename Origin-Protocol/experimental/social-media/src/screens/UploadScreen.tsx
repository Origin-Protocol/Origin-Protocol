import { useState, useRef, FormEvent, useEffect } from 'react';
import { UploadProgress, membershipApi, originApi, resolveApiAssetUrl, syncHistoryApi, videosApi } from '../api/client';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { OriginVerifyResult, VideoMeta } from '../types';
import { SyncHistoryItem } from '../utils/syncHistory';
import { DEFAULT_CREATOR_PLAN } from '../config/pricing';

const RECENT_UPLOAD_KEY = 'origin_recent_upload_video';

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
}

function buildOriginBundleId(userId: string, title: string): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const random = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().slice(0, 8)
    : Math.random().toString(36).slice(2, 10)
  ).toLowerCase();
  const titlePart = slugify(title) || 'untitled';
  return `${userId.slice(0, 8)}.${titlePart}.${ts}.${random}.origin.zip`;
}

export default function UploadScreen() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const fileRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [publishMode, setPublishMode] = useState<'upload' | 'sync'>('upload');
  const [sealedPayload, setSealedPayload] = useState('');
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [syncHistory, setSyncHistory] = useState<SyncHistoryItem[]>([]);
  const [syncHistoryBusy, setSyncHistoryBusy] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [bundleId, setBundleId] = useState('');
  const [protectUpload, setProtectUpload] = useState(false);
  const [useAutoBundle, setUseAutoBundle] = useState(true);
  const [includeCreatorId, setIncludeCreatorId] = useState(true);
  const [includeAssetId, setIncludeAssetId] = useState(true);
  const [includePlatforms, setIncludePlatforms] = useState(true);
  const [includeKeyId, setIncludeKeyId] = useState(true);
  const [showProtectionLogo, setShowProtectionLogo] = useState(true);
  const [embedRandomizedWatermark, setEmbedRandomizedWatermark] = useState(true);
  const [embedInvisibleProofData, setEmbedInvisibleProofData] = useState(true);
  const [enableGFilterReveal, setEnableGFilterReveal] = useState(true);
  const [protectionPolicyProfile, setProtectionPolicyProfile] = useState<'permissive' | 'standard' | 'strict'>('standard');
  const [governanceLedgerCid, setGovernanceLedgerCid] = useState('');
  const [intendedPlatforms, setIntendedPlatforms] = useState<string>('Meta, Instagram, TikTok');
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<VideoMeta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<UploadProgress | null>(null);
  const [transportLabel, setTransportLabel] = useState<'cloudflare' | 'fallback' | null>(null);
  const [membershipBusy, setMembershipBusy] = useState(false);
  const [membershipMsg, setMembershipMsg] = useState<string | null>(null);
  const [membershipActive, setMembershipActive] = useState<boolean>(Boolean(user?.creatorKeyId));
  const [checkoutEnabled, setCheckoutEnabled] = useState<boolean>(true);
  const [contentHash, setContentHash] = useState<string>('');
  const [hashBusy, setHashBusy] = useState(false);
  const [originVerification, setOriginVerification] = useState<OriginVerifyResult | null>(null);
  const [originVerificationError, setOriginVerificationError] = useState<string | null>(null);

  const memberActive = membershipActive;

  useEffect(() => {
    let mounted = true;

    async function hydrateMembership() {
      try {
        const status = await membershipApi.status();
        if (!mounted) return;
        setMembershipActive(status.active);
        setCheckoutEnabled(status.checkoutEnabled);
        localStorage.setItem('origin_user', JSON.stringify(status.user));
      } catch {
        // Non-fatal for upload page rendering
      }
    }

    void hydrateMembership();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    const billingStatus = query.get('billing');
    if (!billingStatus) return;

    if (billingStatus === 'canceled') {
      setMembershipMsg('Stripe checkout was canceled. You can retry anytime.');
      return;
    }

    if (billingStatus !== 'success') return;

    let cancelled = false;
    async function refreshMembershipAfterCheckout() {
      try {
        const status = await membershipApi.status();
        if (cancelled) return;
        setMembershipActive(status.active);
        setCheckoutEnabled(status.checkoutEnabled);
        localStorage.setItem('origin_user', JSON.stringify(status.user));
        setMembershipMsg(
          status.active
            ? 'Stripe payment confirmed. Creator protection is active.'
            : 'Stripe payment received. Membership will activate once webhook sync completes.'
        );
      } catch {
        if (!cancelled) {
          setMembershipMsg('Stripe payment received. Refresh in a moment to confirm membership status.');
        }
      }
    }

    void refreshMembershipAfterCheckout();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function digestFile(file: File) {
      setHashBusy(true);
      setOriginVerification(null);
      setOriginVerificationError(null);
      try {
        if (!crypto?.subtle) {
          setContentHash('');
          return;
        }

        const buffer = await file.arrayBuffer();
        const digest = await crypto.subtle.digest('SHA-256', buffer);
        const hashHex = Array.from(new Uint8Array(digest))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
        if (!cancelled) setContentHash(hashHex);
      } catch {
        if (!cancelled) setContentHash('');
      } finally {
        if (!cancelled) setHashBusy(false);
      }
    }

    if (!selectedFile) {
      setContentHash('');
      setHashBusy(false);
      return;
    }

    void digestFile(selectedFile);

    return () => {
      cancelled = true;
    };
  }, [selectedFile]);

  if (!user) {
    return <p>Please <a href="/login">log in</a> to upload videos.</p>;
  }
  const currentUser = user;

  useEffect(() => {
    let mounted = true;
    async function hydrateSyncHistory() {
      try {
        const res = await syncHistoryApi.listMine();
        if (!mounted) return;
        setSyncHistory(res.items);
      } catch {
        if (!mounted) return;
        setSyncHistory([]);
      }
    }
    void hydrateSyncHistory();
    return () => {
      mounted = false;
    };
  }, [currentUser.id]);

  const selectedPlatforms = intendedPlatforms
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  function buildProtectedDescription(base: string): string {
    const flags: string[] = [];
    if (includeCreatorId) flags.push('creator-id');
    if (includeAssetId) flags.push('asset-id');
    if (includePlatforms) flags.push('platform-targets');
    if (includeKeyId) flags.push('key-id');
    if (showProtectionLogo) flags.push('origin-logo');
    if (embedRandomizedWatermark) flags.push('randomized-watermark');
    if (embedInvisibleProofData) flags.push('embedded-proof-payload');
    if (enableGFilterReveal) flags.push('g-filter-ready');
    flags.push(`policy-${protectionPolicyProfile}`);
    if (governanceLedgerCid.trim()) flags.push('governance-ledger-cid');

    const protectionMeta = {
      protected: true,
      options: flags,
      platforms: includePlatforms ? selectedPlatforms : [],
      revealMode: enableGFilterReveal ? 'g-filter' : 'off',
      policyProfile: protectionPolicyProfile,
      governanceLedgerCid: governanceLedgerCid.trim() || undefined,
      revocationPath: '/api/origin/revocations',
    };

    const safeBase = base.trim();
    const encoded = JSON.stringify(protectionMeta);
    return safeBase
      ? `${safeBase}\n\n[origin_protection]${encoded}`
      : `[origin_protection]${encoded}`;
  }

  async function startStripeCheckout() {
    setMembershipBusy(true);
    setMembershipMsg(null);
    try {
      const session = await membershipApi.createCheckoutSession({
        productId: DEFAULT_CREATOR_PLAN.productId,
        mode: DEFAULT_CREATOR_PLAN.mode,
        billingType: DEFAULT_CREATOR_PLAN.billingType,
      });
      if (session.checkoutBypassed && session.user) {
        setMembershipActive(true);
        localStorage.setItem('origin_user', JSON.stringify(session.user));
        setMembershipMsg('Creator protection unlocked for this admin account.');
        return;
      }

      if (!session.url) {
        setMembershipMsg('Unable to start Stripe checkout right now.');
        return;
      }

      window.location.href = session.url;
    } catch (err) {
      setMembershipMsg((err as Error).message || 'Unable to start Stripe checkout right now.');
    } finally {
      setMembershipBusy(false);
    }
  }

  async function openBillingPortal() {
    setMembershipBusy(true);
    setMembershipMsg(null);
    try {
      const session = await membershipApi.createPortalSession();
      if (!session.url) {
        setMembershipMsg('Unable to open billing portal right now.');
        return;
      }
      window.open(session.url, '_blank', 'noopener,noreferrer');
    } catch (err) {
      setMembershipMsg((err as Error).message || 'Unable to open billing portal right now.');
    } finally {
      setMembershipBusy(false);
    }
  }

  async function runSealedSync(payloadRaw: string, fromHistory = false) {
    setUploading(true);
    setError(null);
    setOriginVerification(null);
    setOriginVerificationError(null);
    setProgress({ stage: 'preparing', percent: 4, message: 'Validating sealed payload…' });
    setTransportLabel(null);

    let parsedPayload: {
      creatorId?: string;
      title?: string;
      description?: string;
      videoUrl?: string;
      originBundleId?: string;
      assetId?: string;
      keyId?: string;
      contentHash?: string;
      originId?: string;
      originPolicy?: string;
      governanceLedgerCid?: string;
    } | null = null;

    try {
      parsedPayload = JSON.parse(payloadRaw) as {
        creatorId?: string;
        title?: string;
        description?: string;
        videoUrl?: string;
        originBundleId?: string;
        assetId?: string;
        keyId?: string;
        contentHash?: string;
        originId?: string;
        originPolicy?: string;
        governanceLedgerCid?: string;
      };

      if (!parsedPayload.title?.trim()) {
        setError('Sealed payload requires a title.');
        return;
      }
      if (!parsedPayload.videoUrl?.trim()) {
        setError('Sealed payload requires videoUrl.');
        return;
      }

      setProgress({ stage: 'finalizing', percent: 62, message: 'Syncing creator-tool payload…' });
      const synced = await videosApi.publishSealed({
        creatorId: parsedPayload.creatorId,
        title: parsedPayload.title.trim(),
        description: parsedPayload.description,
        videoUrl: parsedPayload.videoUrl.trim(),
        originBundleId: parsedPayload.originBundleId,
        assetId: parsedPayload.assetId,
        keyId: parsedPayload.keyId,
        contentHash: parsedPayload.contentHash,
        originId: parsedPayload.originId,
        originPolicy: parsedPayload.originPolicy,
        governanceLedgerCid: parsedPayload.governanceLedgerCid,
      });

      try {
        const history = await syncHistoryApi.create({
          status: 'success',
          title: parsedPayload.title.trim(),
          videoUrl: parsedPayload.videoUrl.trim(),
          videoId: synced.video.id,
          message: 'Synced and published',
          payloadJson: payloadRaw,
        });
        setSyncHistory(history.items);
      } catch {
        // Non-fatal for publish flow
      }

      setProgress({ stage: 'done', percent: 100, message: 'Synced and published — sending to feed…' });
      setSyncMsg(fromHistory ? 'History payload re-synced successfully.' : 'Creator tool payload synced successfully.');
      window.localStorage.setItem(RECENT_UPLOAD_KEY, JSON.stringify(synced.video));
      setResult(synced.video);

      setTimeout(() => {
        navigate('/', { replace: true });
      }, 650);
    } catch (err) {
      const message = (err as Error).message || 'Unable to sync sealed payload.';
      setError(message);
      try {
        const history = await syncHistoryApi.create({
          status: 'failed',
          title: parsedPayload?.title?.trim() || 'Invalid/Unknown title',
          videoUrl: parsedPayload?.videoUrl?.trim() || '',
          message,
          payloadJson: payloadRaw,
        });
        setSyncHistory(history.items);
      } catch {
        // Non-fatal for publish flow
      }
    } finally {
      setUploading(false);
    }
  }

  async function clearSyncHistory() {
    setSyncHistoryBusy(true);
    setSyncMsg(null);
    try {
      await syncHistoryApi.clearMine();
      setSyncHistory([]);
      setSyncMsg('Sync history cleared.');
    } catch (err) {
      setSyncMsg((err as Error).message || 'Unable to clear sync history.');
    } finally {
      setSyncHistoryBusy(false);
    }
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSyncMsg(null);

    if (publishMode === 'sync') {
      await runSealedSync(sealedPayload);
      return;
    }

    const file = selectedFile ?? fileRef.current?.files?.[0];
    if (!file) { setError('Please select a video file.'); return; }
    if (!title.trim()) { setError('Title is required.'); return; }
    if (protectUpload && !memberActive) {
      setError('Creator protection requires membership activation first.');
      return;
    }

    setUploading(true);
    setError(null);
    setOriginVerification(null);
    setOriginVerificationError(null);
    setProgress({ stage: 'preparing', percent: 1, message: 'Preparing upload…' });
    setTransportLabel(null);
    try {
      const resolvedBundleId = (protectUpload && useAutoBundle
        ? buildOriginBundleId(currentUser.id, title.trim())
        : protectUpload
          ? bundleId.trim() || undefined
          : undefined);
      const resolvedAssetId = resolvedBundleId;
      const resolvedKeyId = currentUser.creatorKeyId ?? undefined;

      const resolvedDescription = protectUpload
        ? buildProtectedDescription(description)
        : description.trim() || undefined;
      const protectionOptions = [
        includeCreatorId ? 'creator-id' : '',
        includeAssetId ? 'asset-id' : '',
        includePlatforms ? 'platform-targets' : '',
        includeKeyId ? 'key-id' : '',
        showProtectionLogo ? 'origin-logo' : '',
        embedRandomizedWatermark ? 'randomized-watermark' : '',
        embedInvisibleProofData ? 'embedded-proof-payload' : '',
        enableGFilterReveal ? 'g-filter-ready' : '',
        `policy:${protectionPolicyProfile}`,
        governanceLedgerCid.trim() ? 'governance-ledger-cid' : '',
      ].filter(Boolean);

      let video: VideoMeta;
      try {
        setTransportLabel('cloudflare');
        const cf = await videosApi.uploadWithCloudflare({
          file,
          title: title.trim(),
          description: resolvedDescription,
          originBundleId: resolvedBundleId,
          assetId: resolvedAssetId,
          keyId: resolvedKeyId,
          contentHash: contentHash || undefined,
          protectedUpload: protectUpload,
          protectionOptions,
          intendedPlatforms: includePlatforms ? selectedPlatforms : [],
          originPolicy: protectUpload ? protectionPolicyProfile : undefined,
          governanceLedgerCid: protectUpload ? (governanceLedgerCid.trim() || undefined) : undefined,
        }, setProgress);
        video = cf.video;
      } catch {
        setTransportLabel('fallback');
        setProgress({ stage: 'uploading', percent: 4, message: 'Switching to resilient upload path…' });
        const fd = new FormData();
        fd.append('video', file);
        fd.append('title', title.trim());
        if (resolvedDescription) fd.append('description', resolvedDescription);
        if (resolvedBundleId) fd.append('originBundleId', resolvedBundleId);
        if (resolvedAssetId) fd.append('assetId', resolvedAssetId);
        if (resolvedKeyId) fd.append('keyId', resolvedKeyId);
        if (contentHash) fd.append('contentHash', contentHash);
        if (protectUpload) fd.append('originPolicy', protectionPolicyProfile);
        if (protectUpload && governanceLedgerCid.trim()) fd.append('governanceLedgerCid', governanceLedgerCid.trim());
        fd.append('protectedUpload', protectUpload ? 'true' : 'false');
        if (protectionOptions.length > 0) {
          fd.append('protectionOptions', JSON.stringify(protectionOptions));
        }
        if (includePlatforms && selectedPlatforms.length > 0) {
          fd.append('intendedPlatforms', JSON.stringify(selectedPlatforms));
        }

        const fallback = await videosApi.upload(fd, setProgress);
        video = fallback.video;
      }

      if (
        protectUpload &&
        resolvedBundleId &&
        currentUser.creatorKeyId &&
        contentHash
      ) {
        try {
          const verify = await originApi.verify({
            creatorId: currentUser.id,
            keyId: currentUser.creatorKeyId,
            assetId: resolvedBundleId,
            contentHash,
          });
          setOriginVerification(verify);
        } catch (verifyErr) {
          setOriginVerificationError((verifyErr as Error).message || 'Unable to verify Origin proof right now.');
        }
      }

      setProgress({ stage: 'done', percent: 100, message: 'Published — sending to feed…' });
      window.localStorage.setItem(RECENT_UPLOAD_KEY, JSON.stringify(video));
      setResult(video);

      setTimeout(() => {
        navigate('/', { replace: true });
      }, 650);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setUploading(false);
    }
  }

  if (result) {
    return (
      <div style={{ maxWidth: 480, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>
        <h2>Upload successful!</h2>
        <p><strong>{result.title}</strong></p>
        {result.originVerified && (
          <p style={{ color: 'green' }}>✅ Origin Protocol ownership verified</p>
        )}
        {!result.originVerified && originVerification?.ok && (
          <p style={{ color: '#22c55e' }}>✅ Origin proof check completed for this upload</p>
        )}
        {!result.originVerified && originVerification && !originVerification.ok && (
          <p style={{ color: '#f59e0b' }}>⚠️ Origin proof check returned review reasons (see below).</p>
        )}
        {originVerification?.reasons?.length ? (
          <ul style={{ marginTop: 8, color: '#f3f4f6', fontSize: 13 }}>
            {originVerification.reasons.slice(0, 3).map((reason) => (
              <li key={`${reason.code}-${reason.message}`}>{reason.message}</li>
            ))}
          </ul>
        ) : null}
        {originVerificationError ? (
          <p style={{ color: '#f59e0b', fontSize: 13 }}>Origin verification pending: {originVerificationError}</p>
        ) : null}
        <video src={resolveApiAssetUrl(result.videoUrl)} controls style={{ width: '100%' }} />
        <button onClick={() => setResult(null)}>Upload another</button>
      </div>
    );
  }

  return (
    <main style={{ maxWidth: 560, margin: '0 auto', padding: 12, color: '#e5e7eb' }}>
      <h2>Upload a video</h2>
      <p style={{ marginTop: 0, color: '#9ca3af' }}>
        Publish fast by default, or enable Origin creator protection options when needed.
      </p>

      <div style={{ marginBottom: 10, border: '1px solid #1f2937', borderRadius: 12, padding: 10, background: '#0b1220' }}>
        <strong style={{ color: '#e5e7eb' }}>Publish Mode</strong>
        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
          <button
            type="button"
            onClick={() => setPublishMode('upload')}
            style={{
              padding: '7px 10px',
              borderRadius: 999,
              border: '1px solid #374151',
              background: publishMode === 'upload' ? '#111827' : 'transparent',
              color: '#fff',
              cursor: 'pointer',
            }}
          >
            Standard upload
          </button>
          <button
            type="button"
            onClick={() => setPublishMode('sync')}
            style={{
              padding: '7px 10px',
              borderRadius: 999,
              border: '1px solid #374151',
              background: publishMode === 'sync' ? '#111827' : 'transparent',
              color: '#fff',
              cursor: 'pointer',
            }}
          >
            Creator Tool Sync
          </button>
        </div>
        <p style={{ margin: '8px 0 0', fontSize: 12, color: '#9ca3af' }}>
          Use sync mode to ingest pre-sealed JSON payloads from your creator tool.
          {' '}
          <Link to="/help#publish-modes" style={{ color: '#93c5fd' }}>Learn modes</Link>
        </p>
      </div>

      <div style={{ marginBottom: 10, border: '1px solid #1f2937', borderRadius: 12, padding: 10, background: '#0b1220' }}>
        <strong style={{ color: '#e5e7eb' }}>Membership</strong>
        <p style={{ margin: '6px 0', fontSize: 13, color: '#9ca3af' }}>
          Status: {memberActive ? 'Active ✅' : 'Not active'}
        </p>
        {!checkoutEnabled && !memberActive && (
          <p style={{ margin: '6px 0', fontSize: 13, color: '#fca5a5' }}>
            Stripe is not configured on the server yet.
          </p>
        )}
        {!memberActive && (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={() => void startStripeCheckout()}
              disabled={membershipBusy || !checkoutEnabled}
              style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff' }}
            >
              {membershipBusy ? 'Opening checkout…' : 'Subscribe with Stripe'}
            </button>
          </div>
        )}
        {memberActive && (
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={() => void openBillingPortal()}
              disabled={membershipBusy}
              style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #0f766e', background: '#0f766e', color: '#fff' }}
            >
              {membershipBusy ? 'Opening portal…' : 'Manage billing'}
            </button>
          </div>
        )}
        {membershipMsg && <p style={{ margin: '8px 0 0', color: '#cbd5e1', fontSize: 13 }}>{membershipMsg}</p>}
      </div>

      <form onSubmit={(e) => void handleSubmit(e)} style={{ display: 'grid', gap: 10, background: 'rgba(2,6,23,0.8)', border: '1px solid #1f2937', borderRadius: 14, padding: 12 }}>
        {publishMode === 'upload' ? (
          <>
            <div>
              <label>Video file<br />
                <input
                  ref={fileRef}
                  type="file"
                  accept="video/*"
                  required
                  onChange={(e) => {
                    setSelectedFile(e.currentTarget.files?.[0] ?? null);
                  }}
                />
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
              <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input
                  type="checkbox"
                  checked={protectUpload}
                  onChange={(e) => setProtectUpload(e.target.checked)}
                  disabled={!memberActive}
                />
                Protect this upload with Origin options (members)
              </label>
            </div>
          </>
        ) : (
          <>
            <div style={{ border: '1px solid #1f2937', borderRadius: 10, padding: 10, background: '#0f172a' }}>
              <label>
                Sealed payload JSON
                <textarea
                  value={sealedPayload}
                  onChange={(e) => setSealedPayload(e.target.value)}
                  rows={10}
                  style={{ width: '100%', marginTop: 6 }}
                  placeholder='{"title":"...","videoUrl":"https://...","originBundleId":"...","assetId":"...","keyId":"...","contentHash":"..."}'
                />
              </label>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
                <button
                  type="button"
                  onClick={() => setSealedPayload(JSON.stringify({
                    title: 'Synced sealed publish',
                    description: 'Imported from creator tool',
                    videoUrl: 'https://example.com/path/to/video.mp4',
                    originBundleId: `${currentUser.id.slice(0, 8)}.sealed.sample.origin.zip`,
                    assetId: `${currentUser.id.slice(0, 8)}.sealed.sample.origin.zip`,
                    keyId: currentUser.creatorKeyId ?? 'your-key-id',
                    contentHash: 'replace-with-sha256-content-hash',
                    originPolicy: protectionPolicyProfile,
                    governanceLedgerCid: governanceLedgerCid || 'sha256:replace-with-governance-ledger-cid',
                  }, null, 2))}
                  style={{ padding: '6px 10px', borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff' }}
                >
                  Insert sample payload
                </button>
              </div>
              <p style={{ margin: '8px 0 0', fontSize: 12, color: '#9ca3af' }}>
                Required keys: <strong>title</strong>, <strong>videoUrl</strong>. Add <strong>originBundleId</strong>, <strong>assetId</strong>, <strong>keyId</strong>, and <strong>contentHash</strong> for full verification sync.
                {' '}
                <Link to="/help#verification" style={{ color: '#93c5fd' }}>Key field guide</Link>
              </p>
            </div>

            <div style={{ border: '1px solid #1f2937', borderRadius: 10, padding: 10, background: '#0b1220' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <strong>Sync history</strong>
                <button
                  type="button"
                  onClick={() => void clearSyncHistory()}
                  disabled={syncHistoryBusy || syncHistory.length === 0}
                  style={{ padding: '5px 8px', borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff' }}
                >
                  {syncHistoryBusy ? 'Clearing…' : 'Clear'}
                </button>
              </div>
              <p style={{ margin: '6px 0 8px', fontSize: 12, color: '#9ca3af' }}>
                Recent creator-tool sync attempts with quick payload reload/re-run.
                {' '}
                <Link to="/help#sync-history" style={{ color: '#93c5fd' }}>How sync history works</Link>
              </p>
              {syncHistory.length === 0 ? (
                <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>No sync attempts yet.</p>
              ) : (
                <div style={{ display: 'grid', gap: 8 }}>
                  {syncHistory.slice(0, 6).map((item) => (
                    <div key={item.id} style={{ border: '1px solid #1f2937', borderRadius: 8, padding: 8, background: '#0f172a' }}>
                      <p style={{ margin: 0, fontSize: 12, color: '#e5e7eb' }}>
                        <strong>{item.status === 'success' ? '✅' : '❌'}</strong> {item.title}
                      </p>
                      <p style={{ margin: '3px 0 0', fontSize: 11, color: '#9ca3af' }}>
                        {new Date(item.createdAt).toLocaleString()} {item.message ? `• ${item.message}` : ''}
                      </p>
                      <div style={{ display: 'flex', gap: 6, marginTop: 6, flexWrap: 'wrap' }}>
                        <button
                          type="button"
                          onClick={() => {
                            setPublishMode('sync');
                            setSealedPayload(item.payloadJson);
                            setSyncMsg('Loaded payload from sync history.');
                          }}
                          style={{ padding: '5px 8px', borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff' }}
                        >
                          Load payload
                        </button>
                        <button
                          type="button"
                          onClick={() => void runSealedSync(item.payloadJson, true)}
                          disabled={uploading}
                          style={{ padding: '5px 8px', borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff' }}
                        >
                          Re-run
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}

        {publishMode === 'upload' && protectUpload && (
          <>
            <div style={{ border: '1px solid #1f2937', borderRadius: 10, padding: 10, background: '#0f172a' }}>
              <strong>Protection options</strong>
              <div style={{ display: 'grid', gap: 6, marginTop: 8 }}>
                <label>
                  Protection policy profile
                  <select
                    value={protectionPolicyProfile}
                    onChange={(e) => setProtectionPolicyProfile(e.target.value as 'permissive' | 'standard' | 'strict')}
                    style={{ marginLeft: 8 }}
                  >
                    <option value="permissive">Permissive</option>
                    <option value="standard">Standard</option>
                    <option value="strict">Strict</option>
                  </select>
                </label>
                <label><input type="checkbox" checked={includeCreatorId} onChange={(e) => setIncludeCreatorId(e.target.checked)} /> Include creator ID</label>
                <label><input type="checkbox" checked={includeAssetId} onChange={(e) => setIncludeAssetId(e.target.checked)} /> Include asset ID</label>
                <label><input type="checkbox" checked={includePlatforms} onChange={(e) => setIncludePlatforms(e.target.checked)} /> Include intended platforms</label>
                <label><input type="checkbox" checked={includeKeyId} onChange={(e) => setIncludeKeyId(e.target.checked)} /> Include key ID</label>
                <label><input type="checkbox" checked={showProtectionLogo} onChange={(e) => setShowProtectionLogo(e.target.checked)} /> Show Origin protection logo in cards</label>
                <label><input type="checkbox" checked={embedRandomizedWatermark} onChange={(e) => setEmbedRandomizedWatermark(e.target.checked)} /> Embed randomized invisible watermark metadata</label>
                <label><input type="checkbox" checked={embedInvisibleProofData} onChange={(e) => setEmbedInvisibleProofData(e.target.checked)} /> Embed Origin proof payload metadata</label>
                <label><input type="checkbox" checked={enableGFilterReveal} onChange={(e) => setEnableGFilterReveal(e.target.checked)} /> Enable G-Filter reveal overlay on feed</label>
              </div>
              <div style={{ marginTop: 8 }}>
                <label>
                  Governance ledger CID (optional)<br />
                  <input
                    value={governanceLedgerCid}
                    onChange={(e) => setGovernanceLedgerCid(e.target.value)}
                    style={{ width: '100%' }}
                    placeholder="sha256:..."
                  />
                </label>
              </div>
            </div>

            <div>
              <label>Intended platforms (comma-separated)<br />
                <input
                  value={intendedPlatforms}
                  onChange={(e) => setIntendedPlatforms(e.target.value)}
                  style={{ width: '100%' }}
                  placeholder="Meta, Instagram, TikTok"
                />
              </label>
            </div>

            <div style={{ border: '1px solid #1f2937', borderRadius: 10, padding: 10, background: '#0b1220' }}>
              <strong>Origin proof preview</strong>
              <p style={{ margin: '6px 0', fontSize: 12, color: '#9ca3af' }}>
                This preview is used for optional verify checks after publish.
                {' '}
                <Link to="/help#verification" style={{ color: '#93c5fd' }}>Verification details</Link>
              </p>
              <div style={{ fontSize: 12, color: '#cbd5e1', display: 'grid', gap: 4 }}>
                <span><strong>Creator ID:</strong> {currentUser.id}</span>
                <span><strong>Key ID:</strong> {currentUser.creatorKeyId ?? 'Not set (membership required)'}</span>
                <span><strong>Policy:</strong> {protectionPolicyProfile}</span>
                <span><strong>Governance CID:</strong> {governanceLedgerCid.trim() || 'Not set'}</span>
                <span><strong>Asset ID:</strong> {useAutoBundle && title.trim() ? buildOriginBundleId(currentUser.id, title.trim()) : (bundleId.trim() || 'Will be generated at publish')}</span>
                <span>
                  <strong>SHA-256:</strong>{' '}
                  {hashBusy ? 'Computing…' : (contentHash ? `${contentHash.slice(0, 16)}…${contentHash.slice(-8)}` : 'Select a file to compute')}
                </span>
              </div>
            </div>

            <div>
          <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={useAutoBundle}
              onChange={(e) => setUseAutoBundle(e.target.checked)}
            />
            Auto-generate Origin Bundle ID
          </label>
        </div>

        {!useAutoBundle && (
          <div>
            <label>
              Origin Bundle ID <span style={{ fontSize: 12, color: '#888' }}>(optional)</span><br />
              <input value={bundleId} onChange={(e) => setBundleId(e.target.value)} style={{ width: '100%' }} />
            </label>
          </div>
        )}

        {useAutoBundle && title.trim() && (
          <p style={{ margin: 0, fontSize: 12, color: '#cbd5e1' }}>
            Preview ID: <code>{buildOriginBundleId(currentUser.id, title.trim())}</code>
          </p>
        )}
          </>
        )}

        <div style={{ border: '1px solid #e5e7eb', borderRadius: 10, padding: 10, background: '#f9fafb' }}>
          <strong>Upload pipeline</strong>
          <p style={{ margin: '6px 0 0', fontSize: 13, color: '#4b5563' }}>
            {publishMode === 'upload'
              ? '1) Optional protection metadata + ID → 2) Try Cloudflare direct upload → 3) Fallback to standard upload if needed.'
              : '1) Validate sealed JSON → 2) Sync creator-tool payload to platform endpoint → 3) Publish directly to feed.'}
          </p>
        </div>

        {progress && (
          <div style={{ border: '1px solid #374151', borderRadius: 10, padding: 10, background: '#0b1220' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: '#cbd5e1' }}>
              <span>{progress.message}</span>
              <strong>{progress.percent}%</strong>
            </div>
            <div style={{ height: 10, marginTop: 8, borderRadius: 999, background: '#1f2937', overflow: 'hidden' }}>
              <div
                style={{
                  width: `${progress.percent}%`,
                  height: '100%',
                  background: 'linear-gradient(90deg, #22d3ee, #a78bfa)',
                  transition: 'width 180ms ease-out',
                }}
              />
            </div>
            <p style={{ margin: '8px 0 0', fontSize: 12, color: '#9ca3af' }}>
              Path: {transportLabel === 'cloudflare' ? 'Cloudflare Stream' : transportLabel === 'fallback' ? 'Fallback multipart' : 'Preparing'}
            </p>
          </div>
        )}
        {error && <p style={{ color: 'red' }}>{error}</p>}
        {syncMsg && <p style={{ color: '#86efac', margin: 0 }}>{syncMsg}</p>}
        <button type="submit" disabled={uploading} style={{ padding: '10px 12px', borderRadius: 8, border: '1px solid #111827', background: '#111827', color: '#fff' }}>
          {uploading ? 'Publishing…' : publishMode === 'upload' ? 'Upload' : 'Sync & Publish'}
        </button>
      </form>
    </main>
  );
}
