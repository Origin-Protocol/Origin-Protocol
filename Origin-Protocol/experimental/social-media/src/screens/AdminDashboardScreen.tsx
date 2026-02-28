import { CSSProperties, FormEvent, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { adminApi, membershipApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';

export default function AdminDashboardScreen() {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dashboard, setDashboard] = useState<Awaited<ReturnType<typeof adminApi.dashboard>> | null>(null);

  const [newVersion, setNewVersion] = useState('');
  const [newVersionNotes, setNewVersionNotes] = useState('');
  const [newVersionFile, setNewVersionFile] = useState('');
  const [savingVersion, setSavingVersion] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [payoutConfig, setPayoutConfig] = useState<Awaited<ReturnType<typeof adminApi.getPayoutConfig>>['config'] | null>(null);
  const [payoutHistory, setPayoutHistory] = useState<Awaited<ReturnType<typeof adminApi.listPayoutHistory>>['items']>([]);
  const [flaggedAccounts, setFlaggedAccounts] = useState<Awaited<ReturnType<typeof adminApi.listPayoutFlags>>['items']>([]);
  const [runMonthKey, setRunMonthKey] = useState(new Date().toISOString().slice(0, 7));
  const [runRevenue, setRunRevenue] = useState('0');
  const [runInfraCost, setRunInfraCost] = useState('0');
  const [runOpsCost, setRunOpsCost] = useState('0');
  const [runSubRevenue, setRunSubRevenue] = useState('0');
  const [runApiRevenue, setRunApiRevenue] = useState('0');
  const [runBoostRevenue, setRunBoostRevenue] = useState('0');
  const [runMau, setRunMau] = useState('0');
  const [runActiveCreators, setRunActiveCreators] = useState('0');
  const [runApiVerifs, setRunApiVerifs] = useState('0');
  const [flagUserId, setFlagUserId] = useState('');
  const [flagReason, setFlagReason] = useState('Suspicious traffic spike');
  const [flagStatus, setFlagStatus] = useState<'open' | 'reviewed' | 'cleared'>('open');
  const [recommendationConfig, setRecommendationConfig] = useState<Awaited<ReturnType<typeof adminApi.getRecommendationConfig>>['config'] | null>(null);
  const [userSearch, setUserSearch] = useState('');
  const [showAdvancedWeights, setShowAdvancedWeights] = useState(false);
  const [verificationMsg, setVerificationMsg] = useState<string | null>(null);
  const [selectedVideoIds, setSelectedVideoIds] = useState<string[]>([]);
  const [verificationResults, setVerificationResults] = useState<{
    processed?: number;
    checked?: number;
    verified?: number;
    stillVerified?: number;
    failed: number;
    skipped: number;
    revokedOrInvalid?: number;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);

      try {
        const membership = await membershipApi.status();
        if (cancelled) return;

        if (!membership.isAdmin) {
          setAuthorized(false);
          setLoading(false);
          return;
        }

        setAuthorized(true);
        const [data, cfg, history, flags, recCfg] = await Promise.all([
          adminApi.dashboard(),
          adminApi.getPayoutConfig(),
          adminApi.listPayoutHistory(24),
          adminApi.listPayoutFlags(),
          adminApi.getRecommendationConfig(),
        ]);
        if (!cancelled) {
          setDashboard(data);
          setPayoutConfig(cfg.config);
          setPayoutHistory(history.items);
          setFlaggedAccounts(flags.items);
          setRecommendationConfig(recCfg.config);
        }
      } catch (err) {
        if (!cancelled) {
          setError((err as Error).message || 'Failed to load admin dashboard.');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    if (!user) {
      setAuthorized(false);
      setLoading(false);
      return;
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [user]);

  async function refreshDashboard() {
    const [data, cfg, history, flags, recCfg] = await Promise.all([
      adminApi.dashboard(),
      adminApi.getPayoutConfig(),
      adminApi.listPayoutHistory(24),
      adminApi.listPayoutFlags(),
      adminApi.getRecommendationConfig(),
    ]);
    setDashboard(data);
    setPayoutConfig(cfg.config);
    setPayoutHistory(history.items);
    setFlaggedAccounts(flags.items);
    setRecommendationConfig(recCfg.config);
  }

  async function saveRecommendationConfig(e: FormEvent) {
    e.preventDefault();
    if (!recommendationConfig) return;
    setActionBusy('recommendation-config');
    setError(null);
    try {
      await adminApi.updateRecommendationConfig(recommendationConfig);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to update recommendation config.');
    } finally {
      setActionBusy(null);
    }
  }

  async function togglePayoutsEnabled(enabled: boolean) {
    setActionBusy('payout-enabled');
    setError(null);
    try {
      await adminApi.updatePayoutConfig({ enabled });
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to update payout state.');
    } finally {
      setActionBusy(null);
    }
  }

  async function runPayoutMonth(e: FormEvent) {
    e.preventDefault();
    setActionBusy('payout-run');
    setError(null);
    try {
      await adminApi.runMonthlyPayout({
        monthKey: runMonthKey,
        totalRevenue: Number(runRevenue) || 0,
        infrastructureCost: Number(runInfraCost) || 0,
        operatingCost: Number(runOpsCost) || 0,
        subscriptionRevenue: Number(runSubRevenue) || 0,
        apiUsageRevenue: Number(runApiRevenue) || 0,
        boostRevenue: Number(runBoostRevenue) || 0,
        activeMonthlyUsers: Number(runMau) || 0,
        activeCreators: Number(runActiveCreators) || 0,
        monthlyApiVerifications: Number(runApiVerifs) || 0,
      });
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to compute monthly payout run.');
    } finally {
      setActionBusy(null);
    }
  }

  async function saveFlaggedAccount(e: FormEvent) {
    e.preventDefault();
    if (!flagUserId.trim()) return;
    setActionBusy('payout-flag');
    setError(null);
    try {
      await adminApi.upsertPayoutFlag(flagUserId.trim(), {
        reason: flagReason.trim() || 'Suspicious activity',
        status: flagStatus,
      });
      setFlagUserId('');
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to update payout flag.');
    } finally {
      setActionBusy(null);
    }
  }

  async function submitVersion(e: FormEvent) {
    e.preventDefault();
    if (!newVersion.trim()) return;

    setSavingVersion(true);
    setError(null);
    try {
      await adminApi.createToolVersion({
        version: newVersion.trim(),
        notes: newVersionNotes.trim() || undefined,
        fileName: newVersionFile.trim() || undefined,
        isLatest: true,
      });
      setNewVersion('');
      setNewVersionNotes('');
      setNewVersionFile('');
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to create tool version.');
    } finally {
      setSavingVersion(false);
    }
  }

  async function markLatest(versionId: string) {
    setActionBusy(`latest:${versionId}`);
    setError(null);
    try {
      await adminApi.updateToolVersion(versionId, { isLatest: true });
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to mark latest.');
    } finally {
      setActionBusy(null);
    }
  }

  async function toggleForceUpdate(versionId: string, forceUpdate: boolean) {
    setActionBusy(`force:${versionId}`);
    setError(null);
    try {
      await adminApi.updateToolVersion(versionId, { forceUpdate: !forceUpdate });
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to update force-update.');
    } finally {
      setActionBusy(null);
    }
  }

  async function recordDownload(versionId: string) {
    setActionBusy(`dl:${versionId}`);
    setError(null);
    try {
      await adminApi.recordToolDownload(versionId);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to record download.');
    } finally {
      setActionBusy(null);
    }
  }

  async function setCreatorAccess(userId: string, active: boolean) {
    setActionBusy(`access:${userId}`);
    setError(null);
    try {
      await adminApi.setCreatorAccess(userId, active);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to update creator access.');
    } finally {
      setActionBusy(null);
    }
  }

  async function removeVideo(videoId: string) {
    setActionBusy(`video:${videoId}`);
    setError(null);
    try {
      await adminApi.deleteVideo(videoId);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to remove video.');
    } finally {
      setActionBusy(null);
    }
  }

  async function reverifyVideo(videoId: string, force = false) {
    setActionBusy(`verify:${videoId}`);
    setError(null);
    setVerificationMsg(null);
    setVerificationResults(null);
    try {
      const result = await adminApi.verifyNow(videoId, {
        force,
        allowKeyFallback: true,
        allowAdminOverrideOnFailure: true,
      });
      setVerificationMsg(
        result.status === 'verified'
          ? 'Video verification succeeded.'
          : result.status === 'failed'
            ? 'Video verification failed. Review reasons in verification report.'
            : (result.reason ?? 'Video verification skipped.')
      );
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to reverify video.');
    } finally {
      setActionBusy(null);
    }
  }

  async function reverifyFailedVideos() {
    setActionBusy('verify:failed');
    setError(null);
    setVerificationMsg(null);
    try {
      const result = await adminApi.verifyBulk({ limit: 500, unverifiedOnly: true, allowKeyFallback: true });
      setVerificationResults({ processed: result.processed, verified: result.verified, failed: result.failed, skipped: result.skipped });
      setVerificationMsg(
        `Bulk verify completed: processed ${result.processed}, verified ${result.verified}, failed ${result.failed}, skipped ${result.skipped}.`
      );
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to run failed-video reverification.');
    } finally {
      setActionBusy(null);
    }
  }

  async function verifySelectedVideos() {
    if (selectedVideoIds.length === 0) {
      setVerificationMsg('Select at least one video first.');
      return;
    }
    setActionBusy('verify:selected');
    setError(null);
    setVerificationMsg(null);
    try {
      const result = await adminApi.verifyBulk({
        videoIds: selectedVideoIds,
        unverifiedOnly: false,
        allowKeyFallback: true,
      });
      setVerificationResults({ processed: result.processed, verified: result.verified, failed: result.failed, skipped: result.skipped });
      setVerificationMsg(`Selected verify completed for ${result.processed} videos.`);
      setSelectedVideoIds([]);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to verify selected videos.');
    } finally {
      setActionBusy(null);
    }
  }

  async function verifyAllUnverifiedVideos() {
    setActionBusy('verify:all-unverified');
    setError(null);
    setVerificationMsg(null);
    try {
      const result = await adminApi.verifyBulk({
        unverifiedOnly: true,
        allowKeyFallback: true,
        limit: 2000,
      });
      setVerificationResults({ processed: result.processed, verified: result.verified, failed: result.failed, skipped: result.skipped });
      setVerificationMsg(`All-unverified verify completed: ${result.verified} verified, ${result.failed} failed.`);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to verify all unverified videos.');
    } finally {
      setActionBusy(null);
    }
  }

  async function recheckRevokedVideos() {
    setActionBusy('verify:recheck-revoked');
    setError(null);
    setVerificationMsg(null);
    try {
      const result = await adminApi.recheckRevocations({ onlyVerified: true, limit: 2000 });
      setVerificationResults({
        checked: result.checked,
        stillVerified: result.stillVerified,
        failed: result.failed,
        skipped: result.skipped,
        revokedOrInvalid: result.revokedOrInvalid,
      });
      setVerificationMsg(`Revocation re-check completed: ${result.revokedOrInvalid} revoked/invalid.`);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to re-check revocations.');
    } finally {
      setActionBusy(null);
    }
  }

  function toggleSelectedVideo(videoId: string, checked: boolean) {
    setSelectedVideoIds((prev) => {
      if (checked) {
        return prev.includes(videoId) ? prev : [...prev, videoId];
      }
      return prev.filter((id) => id !== videoId);
    });
  }

  function getVideoVerificationStatus(video: import('../types').VideoMeta): {
    label: string;
    color: string;
  } {
    if (video.originVerified) {
      return { label: 'Verified', color: '#86efac' };
    }
    const firstReason = video.originReasons?.[0]?.message;
    if (firstReason) {
      return { label: `Failed: ${firstReason}`, color: '#fca5a5' };
    }
    return { label: 'Pending verification', color: '#fcd34d' };
  }

  async function setUserBan(userId: string, banned: boolean) {
    setActionBusy(`ban:${userId}`);
    setError(null);
    try {
      await adminApi.setUserBan(userId, banned);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to update ban state.');
    } finally {
      setActionBusy(null);
    }
  }

  async function setUserAdminRole(userId: string, active: boolean) {
    setActionBusy(`admin:${userId}`);
    setError(null);
    try {
      await adminApi.setUserAdmin(userId, active);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to update admin role.');
    } finally {
      setActionBusy(null);
    }
  }

  async function resolveReport(reportId: string) {
    setActionBusy(`report:${reportId}`);
    setError(null);
    try {
      await adminApi.resolveReport(reportId);
      await refreshDashboard();
    } catch (err) {
      setError((err as Error).message || 'Failed to resolve report.');
    } finally {
      setActionBusy(null);
    }
  }

  if (!user) {
    return (
      <main style={{ maxWidth: 900, margin: '0 auto', padding: 14, color: '#e5e7eb' }}>
        <h2>Admin Dashboard</h2>
        <p>Please sign in first.</p>
        <Link to="/login" style={{ color: '#93c5fd' }}>Go to login</Link>
      </main>
    );
  }

  if (loading) {
    return <main style={{ maxWidth: 900, margin: '0 auto', padding: 14, color: '#e5e7eb' }}><p>Loading admin dashboard…</p></main>;
  }

  if (!authorized) {
    return (
      <main style={{ maxWidth: 900, margin: '0 auto', padding: 14, color: '#e5e7eb' }}>
        <h2>Admin Dashboard</h2>
        <p>You do not have admin access.</p>
      </main>
    );
  }

  if (!dashboard) {
    return (
      <main style={{ maxWidth: 900, margin: '0 auto', padding: 14, color: '#e5e7eb' }}>
        <h2>Admin Dashboard</h2>
        <p>{error || 'Unable to load dashboard data.'}</p>
      </main>
    );
  }

  const cardStyle: CSSProperties = {
    border: '1px solid #1f2937',
    borderRadius: 12,
    padding: 12,
    background: '#0b1220',
    marginBottom: 12,
  };

  const normalizedUserSearch = userSearch.trim().toLowerCase();
  const filteredUsers = normalizedUserSearch
    ? dashboard.users.filter((item) =>
        item.username.toLowerCase().includes(normalizedUserSearch) ||
        item.displayName.toLowerCase().includes(normalizedUserSearch) ||
        item.email.toLowerCase().includes(normalizedUserSearch)
      )
    : dashboard.users;

  const aiDecisionSummary = recommendationConfig
    ? [
      `AI-adaptive tuning is ${recommendationConfig.aiAdaptiveEnabled ? 'enabled' : 'disabled'}.`,
      `Health weight (${recommendationConfig.weights.health}) and equity weight (${recommendationConfig.weights.equity}) bias recommendations toward well-being and creator fairness.`,
      `Fairness rotation runs every ${recommendationConfig.fairnessRotationFrequency} recommendation cycles to reduce repetitive creator dominance.`,
      `Creator dominance cap is ${recommendationConfig.creatorDominanceCap}, so single-creator overexposure is constrained.`,
      `Health downrank threshold is ${recommendationConfig.healthDownrankThreshold}; low-health signals get deprioritized automatically.`,
    ]
    : [];

  return (
    <main style={{ maxWidth: 1100, margin: '0 auto', padding: 14, color: '#e5e7eb' }}>
      <h2>Origin Admin Dashboard</h2>
      <p style={{ color: '#9ca3af' }}>Signed in as admin: {dashboard.admin.email}</p>
      {error && <p style={{ color: '#fca5a5' }}>{error}</p>}

      <section style={{ ...cardStyle, display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
        <div><strong>Users</strong><div>{dashboard.summary.usersTotal}</div></div>
        <div><strong>Videos</strong><div>{dashboard.summary.videosTotal}</div></div>
        <div><strong>Bundles</strong><div>{dashboard.summary.bundlesTotal}</div></div>
        <div><strong>Verified</strong><div>{dashboard.summary.verification.verified}</div></div>
        <div><strong>Verification Failed</strong><div>{dashboard.summary.verification.failed}</div></div>
        <div><strong>Creator Subscriptions</strong><div>{dashboard.summary.creatorSubscriptions}</div></div>
        <div><strong>Banned Users</strong><div>{dashboard.summary.bannedUsers}</div></div>
        <div><strong>Open Reports</strong><div>{dashboard.summary.openReports}</div></div>
        <div><strong>Usage Events</strong><div>{dashboard.summary.usageEventsTotal}</div></div>
        <div><strong>Error Logs</strong><div>{dashboard.summary.errorLogsTotal}</div></div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Creator Payout Sustainability Controls</h3>
        <p style={{ color: '#9ca3af', marginTop: 0 }}>
          Payouts are pool-based and never exceed platform-funded pool contributions.
        </p>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
          <strong>Global payouts:</strong>
          <button type="button" onClick={() => void togglePayoutsEnabled(true)} disabled={Boolean(actionBusy)}>Enable</button>
          <button type="button" onClick={() => void togglePayoutsEnabled(false)} disabled={Boolean(actionBusy)}>Disable</button>
          <span style={{ color: '#93c5fd' }}>{payoutConfig?.enabled ? 'Enabled' : 'Disabled'}</span>
        </div>

        {payoutConfig && (
          <div style={{ display: 'grid', gap: 6, gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', marginBottom: 10 }}>
            <div><strong>Min net profit</strong><div>${payoutConfig.thresholds.minMonthlyNetProfit.toLocaleString()}</div></div>
            <div><strong>Min revenue</strong><div>${payoutConfig.thresholds.minMonthlyRevenue.toLocaleString()}</div></div>
            <div><strong>Min MAU</strong><div>{payoutConfig.thresholds.minActiveMonthlyUsers.toLocaleString()}</div></div>
            <div><strong>Min active creators</strong><div>{payoutConfig.thresholds.minActiveCreators.toLocaleString()}</div></div>
            <div><strong>Min API verifications</strong><div>{payoutConfig.thresholds.minMonthlyApiVerifications.toLocaleString()}</div></div>
          </div>
        )}

        <form onSubmit={(e) => void runPayoutMonth(e)} style={{ display: 'grid', gap: 8, marginBottom: 10 }}>
          <h4 style={{ margin: '8px 0 0' }}>Monthly pool run</h4>
          <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))' }}>
            <input value={runMonthKey} onChange={(e) => setRunMonthKey(e.target.value)} placeholder="YYYY-MM" />
            <input value={runRevenue} onChange={(e) => setRunRevenue(e.target.value)} placeholder="Total revenue" />
            <input value={runInfraCost} onChange={(e) => setRunInfraCost(e.target.value)} placeholder="Infrastructure cost" />
            <input value={runOpsCost} onChange={(e) => setRunOpsCost(e.target.value)} placeholder="Operating cost" />
            <input value={runSubRevenue} onChange={(e) => setRunSubRevenue(e.target.value)} placeholder="Subscription revenue" />
            <input value={runApiRevenue} onChange={(e) => setRunApiRevenue(e.target.value)} placeholder="API usage revenue" />
            <input value={runBoostRevenue} onChange={(e) => setRunBoostRevenue(e.target.value)} placeholder="Boost revenue" />
            <input value={runMau} onChange={(e) => setRunMau(e.target.value)} placeholder="Active monthly users" />
            <input value={runActiveCreators} onChange={(e) => setRunActiveCreators(e.target.value)} placeholder="Active creators" />
            <input value={runApiVerifs} onChange={(e) => setRunApiVerifs(e.target.value)} placeholder="Monthly API verifications" />
          </div>
          <button type="submit" disabled={Boolean(actionBusy)} style={{ width: 220 }}>Compute monthly payout run</button>
        </form>

        <h4 style={{ margin: '8px 0' }}>Flagged payout accounts</h4>
        <form onSubmit={(e) => void saveFlaggedAccount(e)} style={{ display: 'grid', gap: 8, marginBottom: 8 }}>
          <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '2fr 3fr 1fr auto' }}>
            <input value={flagUserId} onChange={(e) => setFlagUserId(e.target.value)} placeholder="Creator userId" />
            <input value={flagReason} onChange={(e) => setFlagReason(e.target.value)} placeholder="Reason" />
            <select value={flagStatus} onChange={(e) => setFlagStatus(e.target.value as 'open' | 'reviewed' | 'cleared')}>
              <option value="open">open</option>
              <option value="reviewed">reviewed</option>
              <option value="cleared">cleared</option>
            </select>
            <button type="submit" disabled={Boolean(actionBusy)}>Save flag</button>
          </div>
        </form>

        <div style={{ maxHeight: 180, overflow: 'auto', marginBottom: 8 }}>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead><tr><th align="left">User</th><th align="left">Status</th><th align="left">Reason</th><th align="left">Updated</th></tr></thead>
            <tbody>
              {flaggedAccounts.map((row) => (
                <tr key={row.userId}>
                  <td>{row.userId}</td>
                  <td>{row.status}</td>
                  <td>{row.reason}</td>
                  <td>{new Date(row.updatedAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <h4 style={{ margin: '8px 0' }}>Creator pool history</h4>
        <div style={{ maxHeight: 220, overflow: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead><tr><th align="left">Month</th><th align="left">Pool</th><th align="left">Eligible views</th><th align="left">Distributed</th><th align="left">Rollover</th><th align="left">Status</th></tr></thead>
            <tbody>
              {payoutHistory.map((row: any) => (
                <tr key={row.id}>
                  <td>{row.monthKey}</td>
                  <td>${Number(row.computed?.creatorPoolBeforeDistribution ?? 0).toFixed(2)}</td>
                  <td>{Number(row.computed?.totalEligibleViews ?? 0).toLocaleString()}</td>
                  <td>${Number(row.computed?.distributedTotal ?? 0).toFixed(2)}</td>
                  <td>${Number(row.computed?.rolloverToNextMonth ?? 0).toFixed(2)}</td>
                  <td>{row.computed?.activation?.payoutsActive ? 'Active' : 'Paused'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Origin Recommendation AI Decisions</h3>
        <p style={{ color: '#9ca3af', marginTop: 0 }}>
          Main feed ranking is AI-managed for relevance, provenance trust, health safeguards, and fairness rotation.
        </p>
        {recommendationConfig ? (
          <form onSubmit={(e) => void saveRecommendationConfig(e)} style={{ display: 'grid', gap: 10 }}>
            <div style={{ border: '1px solid #1f2937', borderRadius: 10, padding: 10, background: '#0f172a' }}>
              <p style={{ margin: '0 0 6px', color: '#cbd5e1', fontSize: 13 }}>
                <strong>Current AI policy snapshot</strong>
              </p>
              <ul style={{ margin: 0, paddingLeft: 18, color: '#9ca3af', fontSize: 12, display: 'grid', gap: 4 }}>
                {aiDecisionSummary.map((line) => <li key={line}>{line}</li>)}
              </ul>
            </div>

            <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input type="checkbox" checked={recommendationConfig.aiAdaptiveEnabled} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, aiAdaptiveEnabled: e.target.checked }) : prev)} />
              Enable AI-adaptive weight nudging for ecosystem health
            </label>

            <button type="button" onClick={() => setShowAdvancedWeights((prev) => !prev)} style={{ width: 260 }}>
              {showAdvancedWeights ? 'Hide advanced tuning' : 'Show advanced tuning'}
            </button>

            {showAdvancedWeights ? (
              <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))' }}>
                <label>Interest weight
                  <input value={recommendationConfig.weights.interest} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, weights: { ...prev.weights, interest: Number(e.target.value) || 0 } }) : prev)} />
                </label>
                <label>Community weight
                  <input value={recommendationConfig.weights.community} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, weights: { ...prev.weights, community: Number(e.target.value) || 0 } }) : prev)} />
                </label>
                <label>Provenance weight
                  <input value={recommendationConfig.weights.provenance} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, weights: { ...prev.weights, provenance: Number(e.target.value) || 0 } }) : prev)} />
                </label>
                <label>Health weight
                  <input value={recommendationConfig.weights.health} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, weights: { ...prev.weights, health: Number(e.target.value) || 0 } }) : prev)} />
                </label>
                <label>Equity weight
                  <input value={recommendationConfig.weights.equity} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, weights: { ...prev.weights, equity: Number(e.target.value) || 0 } }) : prev)} />
                </label>
                <label>Fairness rotation frequency
                  <input value={recommendationConfig.fairnessRotationFrequency} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, fairnessRotationFrequency: Number(e.target.value) || 1 }) : prev)} />
                </label>
                <label>Creator dominance cap
                  <input value={recommendationConfig.creatorDominanceCap} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, creatorDominanceCap: Number(e.target.value) || 1 }) : prev)} />
                </label>
                <label>Spotlight boost visibility
                  <input value={recommendationConfig.spotlightBoostVisibility} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, spotlightBoostVisibility: Number(e.target.value) || 0 }) : prev)} />
                </label>
                <label>Health downrank threshold
                  <input value={recommendationConfig.healthDownrankThreshold} onChange={(e) => setRecommendationConfig((prev) => prev ? ({ ...prev, healthDownrankThreshold: Number(e.target.value) || 0 }) : prev)} />
                </label>
              </div>
            ) : null}

            <button type="submit" disabled={Boolean(actionBusy)} style={{ width: 260 }}>Save recommendation settings</button>
          </form>
        ) : (
          <p style={{ color: '#9ca3af' }}>Recommendation config unavailable.</p>
        )}
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Creator Tool Version Control</h3>
        <form onSubmit={(e) => void submitVersion(e)} style={{ display: 'grid', gap: 8, marginBottom: 10 }}>
          <input value={newVersion} onChange={(e) => setNewVersion(e.target.value)} placeholder="Version (e.g. 1.2.0)" />
          <input value={newVersionFile} onChange={(e) => setNewVersionFile(e.target.value)} placeholder="EXE filename (optional)" />
          <textarea value={newVersionNotes} onChange={(e) => setNewVersionNotes(e.target.value)} placeholder="Release notes" rows={2} />
          <button type="submit" disabled={savingVersion} style={{ width: 180 }}>
            {savingVersion ? 'Saving…' : 'Publish new version'}
          </button>
        </form>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead>
              <tr><th align="left">Version</th><th align="left">Latest</th><th align="left">Force Update</th><th align="left">Downloads</th><th align="left">Created</th><th align="left">Actions</th></tr>
            </thead>
            <tbody>
              {dashboard.toolVersions.map((item) => (
                <tr key={item.id}>
                  <td>{item.version}</td>
                  <td>{item.isLatest ? '✅' : ''}</td>
                  <td>{item.forceUpdate ? '✅' : ''}</td>
                  <td>{item.downloadCount}</td>
                  <td>{new Date(item.createdAt).toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <button type="button" onClick={() => void markLatest(item.id)} disabled={Boolean(actionBusy)}>Set latest</button>
                      <button type="button" onClick={() => void toggleForceUpdate(item.id, item.forceUpdate)} disabled={Boolean(actionBusy)}>
                        {item.forceUpdate ? 'Unset force' : 'Force update'}
                      </button>
                      <button type="button" onClick={() => void recordDownload(item.id)} disabled={Boolean(actionBusy)}>+1 download</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>User & Subscription Overview</h3>
        <p style={{ color: '#9ca3af', marginTop: 0 }}>Stripe-backed creator access list.</p>
        <input
          value={userSearch}
          onChange={(e) => setUserSearch(e.target.value)}
          placeholder="Search username, nickname, or email"
          style={{ width: '100%', marginBottom: 8 }}
        />
        <div style={{ maxHeight: 280, overflow: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead>
              <tr><th align="left">User</th><th align="left">Email</th><th align="left">Role</th><th align="left">Creator Access</th><th align="left">Banned</th><th align="left">Created</th><th align="left">Actions</th></tr>
            </thead>
            <tbody>
              {filteredUsers.map((item) => (
                <tr key={item.id}>
                  <td>{item.displayName}</td>
                  <td>{item.email}</td>
                  <td>{item.isAdmin ? 'Admin' : 'User'}</td>
                  <td>{item.creatorKeyId ? 'Active' : 'Inactive'}</td>
                  <td>{item.banned ? '🚫' : '—'}</td>
                  <td>{new Date(item.createdAt).toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        onClick={() => void setCreatorAccess(item.id, !item.creatorKeyId)}
                        disabled={Boolean(actionBusy)}
                      >
                        {item.creatorKeyId ? 'Disable access' : 'Enable access'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void setUserBan(item.id, !item.banned)}
                        disabled={Boolean(actionBusy)}
                        style={item.banned ? { color: '#86efac', borderColor: '#14532d' } : { color: '#fecaca', borderColor: '#7f1d1d' }}
                      >
                        {item.banned ? 'Unban' : 'Ban'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void setUserAdminRole(item.id, !item.isAdmin)}
                        disabled={Boolean(actionBusy)}
                        style={item.isAdmin ? { color: '#bfdbfe', borderColor: '#1d4ed8' } : undefined}
                      >
                        {item.isAdmin ? 'Demote admin' : 'Promote admin'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Report Queue</h3>
        <div style={{ maxHeight: 260, overflow: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead>
              <tr><th align="left">Time</th><th align="left">Video</th><th align="left">Reason</th><th align="left">Status</th><th align="left">Actions</th></tr>
            </thead>
            <tbody>
              {dashboard.reports.slice(0, 200).map((report) => (
                <tr key={report.id}>
                  <td>{new Date(report.createdAt).toLocaleString()}</td>
                  <td>{report.videoId}</td>
                  <td>{report.reason}</td>
                  <td>{report.status}</td>
                  <td>
                    {report.status === 'open' && (
                      <button
                        type="button"
                        onClick={() => void resolveReport(report.id)}
                        disabled={Boolean(actionBusy)}
                      >
                        Resolve
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Content Moderation</h3>
        {verificationMsg ? <p style={{ marginTop: 0, color: '#93c5fd', fontSize: 12 }}>{verificationMsg}</p> : null}
        <div style={{ maxHeight: 280, overflow: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead>
              <tr><th align="left">Select</th><th align="left">Title</th><th align="left">Creator</th><th align="left">Status</th><th align="left">Created</th><th align="left">Actions</th></tr>
            </thead>
            <tbody>
              {dashboard.videos.slice(0, 200).map((video) => (
                <tr key={video.id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedVideoIds.includes(video.id)}
                      onChange={(event) => toggleSelectedVideo(video.id, event.target.checked)}
                      disabled={Boolean(actionBusy)}
                    />
                  </td>
                  <td>{video.title}</td>
                  <td>{video.creatorDisplayName || video.creatorId}</td>
                  <td style={{ color: getVideoVerificationStatus(video).color }}>{getVideoVerificationStatus(video).label}</td>
                  <td>{new Date(video.createdAt).toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <button
                        type="button"
                        onClick={() => void reverifyVideo(video.id, true)}
                        disabled={Boolean(actionBusy)}
                        style={{ color: '#bfdbfe', borderColor: '#1d4ed8' }}
                      >
                        Verify
                      </button>
                      <button
                        type="button"
                        onClick={() => void removeVideo(video.id)}
                        disabled={Boolean(actionBusy)}
                        style={{ color: '#fecaca', borderColor: '#7f1d1d' }}
                      >
                        Remove
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Verification & Bundles</h3>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 8 }}>
          <span>Sealed: {dashboard.summary.verification.sealed}</span>
          <span>Unsealed: {dashboard.summary.verification.unsealed}</span>
          <span>Verified: {dashboard.summary.verification.verified}</span>
          <span>Failed: {dashboard.summary.verification.failed}</span>
          <span>Pending: {dashboard.summary.verification.pending}</span>
          <span>Revoked/Invalid: {dashboard.summary.verification.revokedOrInvalid}</span>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
          <button type="button" onClick={() => void verifySelectedVideos()} disabled={Boolean(actionBusy) || selectedVideoIds.length === 0}>
            Verify selected
          </button>
          <button type="button" onClick={() => void verifyAllUnverifiedVideos()} disabled={Boolean(actionBusy)}>
            Verify all unverified
          </button>
          <button type="button" onClick={() => void recheckRevokedVideos()} disabled={Boolean(actionBusy)}>
            Re-check revoked
          </button>
          <button type="button" onClick={() => void reverifyFailedVideos()} disabled={Boolean(actionBusy)}>
            Verify failed videos (legacy)
          </button>
        </div>
        {verificationResults ? (
          <div style={{ border: '1px solid #1f2937', borderRadius: 8, padding: 8, marginBottom: 8, fontSize: 12 }}>
            <strong>Latest run:</strong>{' '}
            processed {verificationResults.processed ?? verificationResults.checked ?? 0},
            {' '}verified {verificationResults.verified ?? verificationResults.stillVerified ?? 0},
            {' '}failed {verificationResults.failed},
            {' '}skipped {verificationResults.skipped}
            {typeof verificationResults.revokedOrInvalid === 'number' ? `, revoked/invalid ${verificationResults.revokedOrInvalid}` : ''}
          </div>
        ) : null}
        <div style={{ maxHeight: 220, overflow: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead>
              <tr><th align="left">Title</th><th align="left">Bundle</th><th align="left">Verified</th><th align="left">When</th></tr>
            </thead>
            <tbody>
              {dashboard.bundles.slice(0, 120).map((row) => (
                <tr key={row.id}>
                  <td>{row.title}</td>
                  <td>{row.originBundleId}</td>
                  <td>{row.originVerified ? '✅' : '❌'}</td>
                  <td>{new Date(row.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Platform Usage & Billing</h3>
        <p style={{ marginTop: 0, color: '#9ca3af' }}>
          Meter: {dashboard.billing.meterId || 'not set'} ({dashboard.billing.meterEventName})
        </p>
        <div style={{ display: 'flex', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
          <a href={adminApi.usageCsvUrl()} target="_blank" rel="noreferrer" style={{ color: '#93c5fd' }}>Export usage CSV</a>
          <a href={adminApi.billingCsvUrl()} target="_blank" rel="noreferrer" style={{ color: '#93c5fd' }}>Export billing CSV</a>
        </div>
        <div style={{ display: 'grid', gap: 6, gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
          {Object.entries(dashboard.usage.byMetric).map(([metric, value]) => (
            <div key={metric} style={{ border: '1px solid #1f2937', borderRadius: 8, padding: 8 }}>
              <strong>{metric}</strong>
              <div>{value}</div>
            </div>
          ))}
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Error Logs</h3>
        <div style={{ maxHeight: 280, overflow: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13 }}>
            <thead>
              <tr><th align="left">Time</th><th align="left">Source</th><th align="left">Message</th></tr>
            </thead>
            <tbody>
              {dashboard.errorLogs.map((log) => (
                <tr key={log.id}>
                  <td>{new Date(log.createdAt).toLocaleString()}</td>
                  <td>{log.source}</td>
                  <td>{log.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
