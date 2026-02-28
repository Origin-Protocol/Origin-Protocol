import { VideoMeta } from '../types';
import { originApi, resolveApiAssetUrl, videosApi } from '../api/client';
import { useRef, useState } from 'react';
import { useAuth } from '../hooks/useAuth';
import { Link, useNavigate } from 'react-router-dom';
import { buildProvenanceReport, parseProtectionMeta } from '../utils/provenance';

function extractHashtags(text: string): string[] {
  const matches = text.match(/#[a-z0-9_]+/gi) ?? [];
  return [...new Set(matches.map((tag) => tag.toLowerCase()))];
}

function inferTopic(video: VideoMeta): string {
  const text = `${video.title} ${video.description ?? ''}`.toLowerCase();
  if (/music|song|beat|dj|album|rap|sing/.test(text)) return 'music';
  if (/game|gaming|fortnite|roblox|minecraft|fps|stream/.test(text)) return 'gaming';
  if (/cook|recipe|food|kitchen|meal|chef/.test(text)) return 'food';
  if (/travel|trip|city|beach|vacation|flight/.test(text)) return 'travel';
  if (/tech|ai|code|app|software|device|gadget/.test(text)) return 'tech';
  if (/learn|tutorial|class|how to|lesson|tips/.test(text)) return 'education';
  if (/fitness|gym|workout|run|yoga|health/.test(text)) return 'fitness';
  if (/comedy|funny|meme|joke|skit/.test(text)) return 'comedy';
  return 'general';
}

interface Props {
  video: VideoMeta;
  variant?: 'cards' | 'reels' | 'grid';
  priority?: boolean;
  allowDelete?: boolean;
  onDeleted?: (videoId: string) => void;
}

export default function VideoCard({ video, variant = 'cards', allowDelete = false, onDeleted }: Props) {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [liked, setLiked] = useState(false);
  const [likeBusy, setLikeBusy] = useState(false);
  const [likeCount, setLikeCount] = useState(video.likeCount);
  const [comments, setComments] = useState<Array<import('../types').Comment>>([]);
  const [commentsLoaded, setCommentsLoaded] = useState(false);
  const [commentDraft, setCommentDraft] = useState('');
  const [commentBusy, setCommentBusy] = useState(false);
  const [muted, setMuted] = useState(true);
  const [showComments, setShowComments] = useState(false);
  const [showProof, setShowProof] = useState(false);
  const [showGFilter, setShowGFilter] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleted, setDeleted] = useState(false);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportMsg, setReportMsg] = useState<string | null>(null);
  const [reportOpen, setReportOpen] = useState(false);
  const [reportReason, setReportReason] = useState('spam');
  const [reportNotes, setReportNotes] = useState('');
  const [keyStatus, setKeyStatus] = useState<string | null>(null);
  const [keyStatusBusy, setKeyStatusBusy] = useState(false);
  const [keyStatusError, setKeyStatusError] = useState<string | null>(null);
  const [exportMsg, setExportMsg] = useState<string | null>(null);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const likeInFlightRef = useRef(false);
  const isReel = variant === 'reels';
  const isGrid = variant === 'grid';

  const { cleanDescription, protectionMeta } = parseProtectionMeta(video.description);
  const isProtected = Boolean(video.originBundleId) || Boolean(protectionMeta?.protected);
  const hasGFilter = Boolean(
    protectionMeta?.revealMode === 'g-filter' ||
    protectionMeta?.options?.some((option) =>
      ['g-filter-ready', 'randomized-watermark', 'embedded-proof-payload'].includes(option)
    )
  );
  const isCreatorOwner = Boolean(user && user.id === video.creatorId);

  async function handleLike() {
    if (likeBusy || likeInFlightRef.current) return;
    likeInFlightRef.current = true;
    setLikeBusy(true);
    try {
      const res = await videosApi.like(video.id);
      setLiked(res.liked);
      setLikeCount(res.likeCount);
    } catch {
      // ignore — user may not be logged in
    } finally {
      setLikeBusy(false);
      likeInFlightRef.current = false;
    }
  }

  async function loadComments() {
    if (commentsLoaded) return;
    try {
      const res = await videosApi.getComments(video.id);
      setComments(res.comments);
      setCommentsLoaded(true);
    } catch {
      // ignore comment fetch failures to avoid breaking feed
    }
  }

  async function handleSubmitComment() {
    const text = commentDraft.trim();
    if (!text || commentBusy) return;
    setCommentBusy(true);
    try {
      const res = await videosApi.postComment(video.id, text);
      setComments((prev) => [...prev, res.comment]);
      setCommentDraft('');
    } catch {
      // user may be logged out
    } finally {
      setCommentBusy(false);
    }
  }

  async function toggleComments() {
    const next = !showComments;
    setShowComments(next);
    if (next) {
      await loadComments();
    }
  }

  function toggleFullscreen() {
    const node = videoRef.current;
    if (!node) return;
    if (document.fullscreenElement) {
      void document.exitFullscreen();
      return;
    }
    void node.requestFullscreen?.();
  }

  function toggleExpanded() {
    if (!isGrid) return;
    navigate(`/video/${video.id}`);
  }

  async function toggleProof() {
    const next = !showProof;
    setShowProof(next);
    setExportMsg(null);
    if (!next || keyStatus || keyStatusBusy || keyStatusError) return;
    if (!isCreatorOwner || !user?.creatorKeyId) return;

    setKeyStatusBusy(true);
    setKeyStatusError(null);
    try {
      const result = await originApi.keyStatus(video.creatorId, user.creatorKeyId);
      setKeyStatus(result.keyStatus ?? 'unknown');
    } catch (err) {
      setKeyStatusError((err as Error).message || 'Unable to load key status');
    } finally {
      setKeyStatusBusy(false);
    }
  }

  async function handleDeleteVideo() {
    if (!allowDelete || deleting) return;
    const confirmed = window.confirm('Delete this video permanently? This action cannot be undone.');
    if (!confirmed) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await videosApi.delete(video.id);
      setDeleted(true);
      onDeleted?.(video.id);
    } catch (err) {
      setDeleteError((err as Error).message || 'Failed to delete video.');
    } finally {
      setDeleting(false);
    }
  }

  function openReportModal() {
    if (!user) {
      setReportMsg('Please sign in to report content.');
      return;
    }
    setReportOpen(true);
  }

  async function submitReport() {
    if (!user || reportBusy) {
      setReportMsg('Please sign in to report content.');
      return;
    }

    const reason = reportReason.trim();
    if (!reason) {
      setReportMsg('Please enter a reason.');
      return;
    }

    setReportBusy(true);
    setReportMsg(null);
    try {
      await videosApi.report(video.id, { reason, notes: reportNotes.trim() || undefined });
      setReportMsg('Report submitted. Admin team has been notified.');
      setReportOpen(false);
      setReportNotes('');
    } catch (err) {
      setReportMsg((err as Error).message || 'Unable to submit report right now.');
    } finally {
      setReportBusy(false);
    }
  }

  function downloadJson(filename: string, payload: unknown) {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setExportMsg(`${filename} downloaded`);
  }

  async function copyJson(payload: unknown) {
    try {
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      setExportMsg('Proof JSON copied');
    } catch {
      setExportMsg('Copy failed in this browser');
    }
  }

  const uploader = video.creatorDisplayName || video.creatorUsername || 'Unknown creator';
  const canViewProof = Boolean(
    video.originBundleId ||
    video.originVerified ||
    (video.originReasons?.length ?? 0) > 0 ||
    video.originVerificationCheckedAt
  );
  const firstFailureReason = video.originReasons?.[0]?.message;
  const verificationStatusLabel = video.originVerified
    ? 'Verified'
    : firstFailureReason
      ? `Failed: ${firstFailureReason}`
      : 'Pending verification';
  const proofPayload = {
    videoId: video.id,
    title: video.title,
    creatorId: video.creatorId,
    bundleId: video.originBundleId,
    originVerified: video.originVerified,
    checkedAt: video.originVerificationCheckedAt ?? null,
    reasons: video.originReasons ?? [],
  };
  const fullProvenanceReport = buildProvenanceReport(video, 'feed-card');
  const topic = inferTopic(video);
  const hashtags = extractHashtags(`${video.title} ${video.description ?? ''}`).slice(0, 2);

  if (deleted) {
    return null;
  }

  return (
    <article
      style={{
        borderBottom: isReel || isGrid ? 'none' : '1px solid #1f2937',
        borderRadius: isReel ? 18 : 14,
        paddingBottom: isReel || isGrid ? 0 : 16,
        marginBottom: isGrid ? 0 : 16,
        scrollSnapAlign: isReel ? 'start' : undefined,
        minHeight: isReel ? 'calc(100vh - 240px)' : undefined,
        background: isReel ? '#000' : 'linear-gradient(180deg, #0f172a, #111827)',
        overflow: 'hidden',
        position: 'relative',
      }}
    >
      <video
        ref={videoRef}
        src={resolveApiAssetUrl(video.videoUrl)}
        controls={!isReel && !isGrid}
        autoPlay={isReel}
        muted={isReel ? muted : false}
        loop={isReel}
        playsInline
        onClick={toggleExpanded}
        style={{
          width: '100%',
          background: '#000',
          maxHeight: isReel ? 'calc(100vh - 240px)' : (isGrid ? 210 : 520),
          minHeight: isReel ? 420 : undefined,
          objectFit: 'cover',
          cursor: isGrid ? 'zoom-in' : 'default',
        }}
        poster={resolveApiAssetUrl(video.thumbnailUrl) || undefined}
      />

      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-end',
          padding: isReel ? '14px 12px 16px' : (isGrid ? '8px 10px 10px' : '10px 12px 0'),
          marginTop: isReel ? -116 : 0,
          position: isReel ? 'relative' : 'static',
          background: isReel ? 'linear-gradient(180deg, rgba(0,0,0,0), rgba(0,0,0,0.86))' : 'transparent',
        }}
      >
        <div style={{ maxWidth: isReel ? '76%' : '100%' }}>
          <strong style={{ fontSize: isReel ? 18 : (isGrid ? 14 : 16), color: '#fff' }}>{video.title}</strong>
          <p style={{ margin: '4px 0 0', color: '#93c5fd', fontSize: 12 }}>
            by{' '}
            <Link to={`/creator/${video.creatorId}`} style={{ color: '#93c5fd', textDecoration: 'underline' }}>
              {uploader}
            </Link>
          </p>
          {!isGrid && cleanDescription && <p style={{ margin: '6px 0', color: '#d1d5db', fontSize: 14 }}>{cleanDescription}</p>}
          {isGrid && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
              <Link
                to={`/feed?topic=${encodeURIComponent(topic)}`}
                style={{ fontSize: 10, border: '1px solid #374151', borderRadius: 999, padding: '2px 6px', color: '#cbd5e1', background: '#0b1220', textDecoration: 'none' }}
              >
                {topic}
              </Link>
              {hashtags.map((tag) => (
                <Link
                  key={tag}
                  to={`/feed?hashtag=${encodeURIComponent(tag)}`}
                  style={{ fontSize: 10, border: '1px solid #374151', borderRadius: 999, padding: '2px 6px', color: '#93c5fd', background: '#0b1220', textDecoration: 'none' }}
                >
                  {tag}
                </Link>
              ))}
            </div>
          )}
          {isProtected && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginTop: 4 }}>
              <p style={{ margin: 0, fontSize: 12, color: '#67e8f9' }}>🛡 Origin Protected</p>
              {hasGFilter && (
                <button
                  onClick={() => setShowGFilter((prev) => !prev)}
                  style={{
                    fontSize: 11,
                    borderRadius: 999,
                    border: '1px solid #22d3ee',
                    background: showGFilter ? 'rgba(34,211,238,0.2)' : 'rgba(34,211,238,0.08)',
                    color: '#cffafe',
                    cursor: 'pointer',
                    padding: '3px 8px',
                  }}
                >
                  {showGFilter ? 'Hide G-Filter' : 'G-Filter'}
                </button>
              )}
            </div>
          )}
          {canViewProof ? (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginTop: 4 }}>
              <button
                onClick={() => void toggleProof()}
                style={{
                  fontSize: 11,
                  borderRadius: 999,
                  border: '1px solid #0ea5e9',
                  background: 'rgba(14,165,233,0.12)',
                  color: '#bae6fd',
                  cursor: 'pointer',
                  padding: '3px 8px',
                }}
              >
                {showProof ? 'Hide proof' : 'View proof'}
              </button>
            </div>
          ) : null}
          <span style={{ fontSize: 12, color: video.originVerified ? '#86efac' : (firstFailureReason ? '#fca5a5' : '#fcd34d') }}>
            {video.originVerified ? '✅ Verified' : (firstFailureReason ? '❌ Failed verification' : '⏳ Pending verification')}
          </span>
          {isProtected && Array.isArray(protectionMeta?.platforms) && protectionMeta.platforms.length > 0 && (
            <p style={{ margin: '4px 0 0', fontSize: 11, color: '#93c5fd' }}>
              Platforms: {protectionMeta.platforms.join(', ')}
            </p>
          )}
          {!isGrid && canViewProof && (
            <div style={{ marginTop: 6 }}>
              <Link
                to={`/verify/${video.id}`}
                state={{ video }}
                style={{
                  fontSize: 12,
                  color: '#7dd3fc',
                  textDecoration: 'none',
                  border: '1px solid rgba(125,211,252,0.45)',
                  borderRadius: 999,
                  padding: '4px 10px',
                  display: 'inline-block',
                  background: 'rgba(14,165,233,0.12)',
                }}
              >
                Open verification report
              </Link>
            </div>
          )}

        </div>

        <div style={{ display: 'grid', gap: 8 }}>
          <button
            onClick={() => void handleLike()}
            disabled={likeBusy}
            style={{
              background: isReel ? 'rgba(255,255,255,0.12)' : 'transparent',
              border: isReel ? '1px solid rgba(255,255,255,0.25)' : 'none',
              cursor: likeBusy ? 'default' : 'pointer',
              fontSize: 18,
              color: '#fff',
              borderRadius: 999,
              padding: isReel ? '10px 12px' : (isGrid ? '4px 0' : 0),
              opacity: likeBusy ? 0.72 : 1,
            }}
          >
            {liked ? '❤️' : '🤍'} {likeCount}
          </button>
          {isReel && (
            <>
              <button
                onClick={openReportModal}
                style={{
                  background: 'rgba(255,255,255,0.12)',
                  border: '1px solid rgba(255,255,255,0.25)',
                  cursor: 'pointer',
                  fontSize: 14,
                  color: '#fff',
                  borderRadius: 999,
                  padding: '8px 12px',
                }}
              >
                🚩
              </button>
              <button
                onClick={() => setMuted((prev) => !prev)}
                style={{
                  background: 'rgba(255,255,255,0.12)',
                  border: '1px solid rgba(255,255,255,0.25)',
                  cursor: 'pointer',
                  fontSize: 14,
                  color: '#fff',
                  borderRadius: 999,
                  padding: '8px 12px',
                }}
              >
                {muted ? '🔇' : '🔊'}
              </button>
              <button
                onClick={toggleFullscreen}
                style={{
                  background: 'rgba(255,255,255,0.12)',
                  border: '1px solid rgba(255,255,255,0.25)',
                  cursor: 'pointer',
                  fontSize: 14,
                  color: '#fff',
                  borderRadius: 999,
                  padding: '8px 12px',
                }}
              >
                ⛶
              </button>
            </>
          )}
        </div>
        {!isGrid && !isReel ? (
          <div style={{ marginTop: 8 }}>
            <Link
              to={`/video/${video.id}`}
              style={{
                color: '#93c5fd',
                textDecoration: 'none',
                border: '1px solid #1f2937',
                borderRadius: 999,
                padding: '4px 10px',
                fontSize: 12,
                display: 'inline-block',
                background: '#0b1220',
              }}
            >
              Open full page
            </Link>
          </div>
        ) : null}
      </div>

      {showProof && canViewProof && !isGrid && (
        <aside
          style={{
            position: 'absolute',
            right: 10,
            top: isReel ? 84 : 10,
            zIndex: 6,
            width: 340,
            maxWidth: 'calc(100% - 20px)',
            border: '1px solid rgba(56,189,248,0.4)',
            background: 'rgba(2,6,23,0.9)',
            borderRadius: 10,
            padding: '8px 10px',
            boxShadow: '0 12px 32px rgba(0,0,0,0.35)',
          }}
        >
          <p style={{ margin: 0, fontSize: 12, color: '#e0f2fe' }}>
            <strong>Status:</strong> {verificationStatusLabel}
          </p>
          <p style={{ margin: '4px 0 0', fontSize: 12, color: '#cbd5e1' }}>
            <strong>Bundle ID:</strong> {video.originBundleId ?? 'Not published'}
          </p>
          <p style={{ margin: '4px 0 0', fontSize: 12, color: '#cbd5e1' }}>
            <strong>Creator:</strong> {uploader}
          </p>
          {protectionMeta?.options?.length ? (
            <p style={{ margin: '4px 0 0', fontSize: 12, color: '#cbd5e1' }}>
              <strong>Options:</strong> {protectionMeta.options.join(', ')}
            </p>
          ) : null}
          <p style={{ margin: '4px 0 0', fontSize: 12, color: '#cbd5e1' }}>
            <strong>Published:</strong> {new Date(video.createdAt).toLocaleString()}
          </p>
          {isCreatorOwner && user?.creatorKeyId && (
            <p style={{ margin: '4px 0 0', fontSize: 12, color: '#a5f3fc' }}>
              <strong>Creator key status:</strong>{' '}
              {keyStatusBusy ? 'checking…' : (keyStatusError ? `unavailable (${keyStatusError})` : (keyStatus ?? 'unknown'))}
            </p>
          )}
          {isCreatorOwner && user?.creatorKeyId && !keyStatusBusy && !keyStatusError && keyStatus === 'unknown' ? (
            <p style={{ margin: '4px 0 0', fontSize: 11, color: '#fbbf24' }}>
              Key status unknown usually means the key is not yet registered on the Origin ledger.
            </p>
          ) : null}
          {video.originVerificationCheckedAt ? (
            <p style={{ margin: '4px 0 0', fontSize: 11, color: '#bae6fd' }}>
              <strong>Checked:</strong> {new Date(video.originVerificationCheckedAt).toLocaleString()}
            </p>
          ) : null}
          {video.originReasons?.length ? (
            <div style={{ marginTop: 6 }}>
              <p style={{ margin: '0 0 4px', fontSize: 11, color: '#fef3c7' }}><strong>Verification reasons</strong></p>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {video.originReasons.slice(0, 4).map((reason) => (
                  <li key={`${reason.code}-${reason.message}`} style={{ fontSize: 11, color: '#fde68a', marginBottom: 2 }}>
                    {reason.message}
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            !video.originVerified && (
              <p style={{ margin: '6px 0 0', fontSize: 11, color: '#fcd34d' }}>
                Verification reasons not available for this video.
              </p>
            )
          )}

          <p style={{ margin: '6px 0 0', fontSize: 11, color: '#cbd5e1' }}>
            Need interpretation? <Link to="/help#verification" style={{ color: '#93c5fd' }}>Open Help</Link>
          </p>

          <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            <button
              type="button"
              onClick={() => downloadJson(`verification-${video.id}.json`, proofPayload)}
              style={{
                borderRadius: 8,
                border: '1px solid #334155',
                background: '#0f172a',
                color: '#e2e8f0',
                padding: '5px 8px',
                cursor: 'pointer',
                fontSize: 11,
              }}
            >
              Download JSON
            </button>
            <button
              type="button"
              onClick={() => void copyJson(proofPayload)}
              style={{
                borderRadius: 8,
                border: '1px solid #334155',
                background: '#0f172a',
                color: '#e2e8f0',
                padding: '5px 8px',
                cursor: 'pointer',
                fontSize: 11,
              }}
            >
              Copy JSON
            </button>
            <button
              type="button"
              onClick={() => downloadJson(`provenance-report-${video.id}.json`, fullProvenanceReport)}
              style={{
                borderRadius: 8,
                border: '1px solid #334155',
                background: '#0f172a',
                color: '#e2e8f0',
                padding: '5px 8px',
                cursor: 'pointer',
                fontSize: 11,
              }}
            >
              Download full report
            </button>
          </div>
          {exportMsg ? (
            <p style={{ margin: '6px 0 0', fontSize: 11, color: '#93c5fd' }}>{exportMsg}</p>
          ) : null}
        </aside>
      )}

      {showProof && canViewProof && isGrid && (
        <div
          onClick={() => setShowProof(false)}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 90,
            background: 'rgba(0,0,0,0.78)',
            display: 'grid',
            placeItems: 'center',
            padding: 14,
          }}
        >
          <aside
            onClick={(event) => event.stopPropagation()}
            style={{
              width: 'min(92vw, 560px)',
              border: '1px solid rgba(56,189,248,0.4)',
              background: 'rgba(2,6,23,0.96)',
              borderRadius: 12,
              padding: '12px 12px 10px',
              boxShadow: '0 12px 32px rgba(0,0,0,0.45)',
              color: '#e5e7eb',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <strong style={{ color: '#e0f2fe' }}>Origin proof</strong>
              <button
                type="button"
                onClick={() => setShowProof(false)}
                style={{
                  borderRadius: 999,
                  border: '1px solid #334155',
                  background: '#0f172a',
                  color: '#e2e8f0',
                  width: 28,
                  height: 28,
                  cursor: 'pointer',
                }}
                aria-label="Close proof"
              >
                ✕
              </button>
            </div>

            <p style={{ margin: 0, fontSize: 12 }}><strong>Status:</strong> {verificationStatusLabel}</p>
            <p style={{ margin: '4px 0 0', fontSize: 12 }}><strong>Bundle ID:</strong> {video.originBundleId ?? 'Not published'}</p>
            <p style={{ margin: '4px 0 0', fontSize: 12 }}><strong>Creator:</strong> {uploader}</p>
            <p style={{ margin: '4px 0 0', fontSize: 12 }}><strong>Published:</strong> {new Date(video.createdAt).toLocaleString()}</p>

            {video.originReasons?.length ? (
              <div style={{ marginTop: 8 }}>
                <p style={{ margin: '0 0 4px', fontSize: 11, color: '#fef3c7' }}><strong>Verification reasons</strong></p>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {video.originReasons.slice(0, 4).map((reason) => (
                    <li key={`${reason.code}-${reason.message}`} style={{ fontSize: 11, color: '#fde68a', marginBottom: 2 }}>
                      {reason.message}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              <button
                type="button"
                onClick={() => downloadJson(`verification-${video.id}.json`, proofPayload)}
                style={{
                  borderRadius: 8,
                  border: '1px solid #334155',
                  background: '#0f172a',
                  color: '#e2e8f0',
                  padding: '6px 9px',
                  cursor: 'pointer',
                  fontSize: 11,
                }}
              >
                Download JSON
              </button>
              <Link
                to={`/verify/${video.id}`}
                state={{ video }}
                style={{
                  borderRadius: 8,
                  border: '1px solid #334155',
                  background: '#0f172a',
                  color: '#93c5fd',
                  padding: '6px 9px',
                  fontSize: 11,
                  textDecoration: 'none',
                }}
              >
                Open verification report
              </Link>
            </div>
            {exportMsg ? (
              <p style={{ margin: '8px 0 0', fontSize: 11, color: '#93c5fd' }}>{exportMsg}</p>
            ) : null}
          </aside>
        </div>
      )}

      {showGFilter && hasGFilter && (
        <div
          style={{
            position: 'absolute',
            left: 12,
            top: isReel ? 14 : 12,
            zIndex: 7,
            background: 'rgba(2, 6, 23, 0.72)',
            border: '1px solid rgba(34,211,238,0.55)',
            borderRadius: 10,
            padding: '8px 10px',
            color: '#e0f2fe',
            maxWidth: isGrid ? 'calc(100% - 24px)' : 360,
            backdropFilter: 'blur(2px)',
            pointerEvents: 'none',
          }}
        >
          <p style={{ margin: 0, fontSize: 11, color: '#67e8f9' }}>
            G-Filter Reveal · Origin Watermark Signal
          </p>
          <p style={{ margin: '4px 0 0', fontSize: 11 }}>
            <strong>Asset:</strong> {video.originBundleId ?? video.id}
          </p>
          <p style={{ margin: '2px 0 0', fontSize: 11 }}>
            <strong>Creator:</strong> {uploader}
          </p>
          <p style={{ margin: '2px 0 0', fontSize: 11 }}>
            <strong>Proof:</strong> {verificationStatusLabel}
          </p>
          {protectionMeta?.options?.length ? (
            <p style={{ margin: '2px 0 0', fontSize: 11 }}>
              <strong>Signals:</strong> {protectionMeta.options.slice(0, 4).join(', ')}
            </p>
          ) : null}
        </div>
      )}

      <p style={{ margin: isGrid ? '0 10px 8px' : '8px 12px 10px', fontSize: 12, color: '#9ca3af' }}>
        👁 {video.viewCount}  💬 {video.commentCount}  •  {new Date(video.createdAt).toLocaleDateString()}
      </p>

      {reportMsg ? (
        <p style={{ margin: isGrid ? '0 10px 8px' : '0 12px 10px', color: '#93c5fd', fontSize: 12 }}>{reportMsg}</p>
      ) : null}

      {allowDelete && (
        <div style={{ padding: isGrid ? '0 10px 10px' : '0 12px 10px' }}>
          <button
            type="button"
            onClick={() => void handleDeleteVideo()}
            disabled={deleting}
            style={{
              border: '1px solid #7f1d1d',
              background: '#450a0a',
              color: '#fecaca',
              borderRadius: 8,
              padding: '6px 10px',
              cursor: deleting ? 'default' : 'pointer',
              fontSize: 12,
            }}
          >
            {deleting ? 'Deleting…' : 'Delete video'}
          </button>
          {deleteError ? (
            <p style={{ margin: '6px 0 0', color: '#fca5a5', fontSize: 12 }}>{deleteError}</p>
          ) : null}
        </div>
      )}

      {!isGrid && (
      <div style={{ padding: '0 12px 12px' }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={() => void toggleComments()}
            style={{
              border: '1px solid #374151',
              background: '#111827',
              color: '#e5e7eb',
              borderRadius: 8,
              padding: '6px 10px',
              cursor: 'pointer',
              fontSize: 12,
            }}
          >
            {showComments ? 'Hide comments' : 'Show comments'}
          </button>
          <button
            onClick={openReportModal}
            disabled={reportBusy}
            style={{
              border: '1px solid #7f1d1d',
              background: '#450a0a',
              color: '#fecaca',
              borderRadius: 8,
              padding: '6px 10px',
              cursor: 'pointer',
              fontSize: 12,
            }}
          >
            Report
          </button>
        </div>

        {showComments && (
          <div style={{ marginTop: 8, display: 'grid', gap: 6 }}>
            <div style={{ maxHeight: 140, overflowY: 'auto', background: 'rgba(17,24,39,0.75)', borderRadius: 8, padding: 8 }}>
              {comments.length === 0 ? (
                <p style={{ margin: 0, color: '#9ca3af', fontSize: 12 }}>No comments yet.</p>
              ) : comments.map((comment) => (
                <p key={comment.id} style={{ margin: '0 0 6px', color: '#e5e7eb', fontSize: 12 }}>
                  <strong>{comment.authorDisplayName || comment.authorUsername || comment.authorId.slice(0, 8)}:</strong> {comment.text}
                </p>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 6 }}>
              <input
                value={commentDraft}
                onChange={(event) => setCommentDraft(event.target.value)}
                placeholder="Add a comment"
                maxLength={500}
                style={{ flex: 1, borderRadius: 8, border: '1px solid #374151', background: '#0b1220', color: '#fff', padding: '6px 8px' }}
              />
              <button
                onClick={() => void handleSubmitComment()}
                disabled={commentBusy}
                style={{ borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff', padding: '6px 10px', cursor: 'pointer' }}
              >
                {commentBusy ? '…' : 'Post'}
              </button>
            </div>
          </div>
        )}
      </div>
      )}

      {reportOpen && (
        <div
          onClick={() => setReportOpen(false)}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 95,
            background: 'rgba(0,0,0,0.74)',
            display: 'grid',
            placeItems: 'center',
            padding: 14,
          }}
        >
          <div
            onClick={(event) => event.stopPropagation()}
            style={{
              width: 'min(92vw, 520px)',
              border: '1px solid #334155',
              borderRadius: 12,
              background: '#020617',
              color: '#e5e7eb',
              padding: 12,
            }}
          >
            <h4 style={{ margin: '0 0 8px' }}>Report content</h4>
            <p style={{ margin: '0 0 8px', fontSize: 12, color: '#94a3b8' }}>
              Help us review this content by selecting a reason.
            </p>
            <select
              value={reportReason}
              onChange={(event) => setReportReason(event.target.value)}
              style={{ width: '100%', marginBottom: 8, borderRadius: 8, background: '#0f172a', color: '#e2e8f0', border: '1px solid #334155', padding: '8px 10px' }}
            >
              <option value="spam">Spam</option>
              <option value="abuse">Abuse / harassment</option>
              <option value="copyright">Copyright issue</option>
              <option value="misleading-proof">Misleading Origin proof</option>
              <option value="other">Other</option>
            </select>
            <textarea
              value={reportNotes}
              onChange={(event) => setReportNotes(event.target.value)}
              rows={4}
              maxLength={1000}
              placeholder="Optional notes for moderators"
              style={{ width: '100%', borderRadius: 8, background: '#0f172a', color: '#e2e8f0', border: '1px solid #334155', padding: '8px 10px' }}
            />
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 10 }}>
              <button
                type="button"
                onClick={() => setReportOpen(false)}
                style={{ borderRadius: 8, border: '1px solid #334155', background: '#0f172a', color: '#e2e8f0', padding: '6px 10px' }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void submitReport()}
                disabled={reportBusy}
                style={{ borderRadius: 8, border: '1px solid #7f1d1d', background: '#450a0a', color: '#fecaca', padding: '6px 10px' }}
              >
                {reportBusy ? 'Submitting…' : 'Submit report'}
              </button>
            </div>
          </div>
        </div>
      )}
    </article>
  );
}
