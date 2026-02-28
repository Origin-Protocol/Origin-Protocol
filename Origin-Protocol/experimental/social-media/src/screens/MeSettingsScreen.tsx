import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { abigailApi, usersApi } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import type { UserSettings } from '../types';
import SettingsSectionCard from '../components/settings/SettingsSectionCard';
import EditableFieldRow from '../components/settings/EditableFieldRow';

const PRONOUN_OPTIONS = [
  { label: 'Not set', value: '' },
  { label: 'She/Her', value: 'she/her' },
  { label: 'He/Him', value: 'he/him' },
  { label: 'They/Them', value: 'they/them' },
  { label: 'She/They', value: 'she/they' },
  { label: 'He/They', value: 'he/they' },
  { label: 'Prefer not to say', value: 'prefer_not_to_say' },
];

const CONTENT_PREFERENCE_OPTIONS = [
  'Technology',
  'Gaming',
  'Music',
  'Education',
  'Fitness',
  'Business',
  'Art & Design',
  'News',
  'Comedy',
  'Science',
];

function normalizeIdentifier(value: string): string {
  return value.trim();
}

function csvToList(raw: string): string[] {
  return raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function listToCsv(items: string[]): string {
  return items.join(', ');
}

function safeDate(iso: string | undefined): string {
  if (!iso) return '—';
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return iso;
  return new Date(ts).toLocaleString();
}

function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(new Error('Unable to read selected file.'));
    reader.readAsDataURL(file);
  });
}

function buildDefaultSettings(user: { id: string; displayName: string; username: string }): UserSettings {
  const ts = new Date().toISOString();
  return {
    userId: user.id,
    personalInformation: {
      displayName: user.displayName,
      username: user.username,
      bio: '',
      profilePhoto: '',
      bannerPhoto: '',
      pronouns: '',
      birthday: '',
      location: '',
      contactEmail: '',
      phoneNumber: '',
    },
    privacySafety: {
      whoCanMessageMe: 'everyone',
      whoCanSeeMyPosts: 'public',
      blockedUsers: [],
      mutedUsers: [],
      twoFactorAuthEnabled: false,
      loginAlertsEnabled: true,
      pauseAbigailMemoryCollection: false,
    },
    preferences: {
      notificationMode: 'important',
      feedTuning: 'balanced',
      contentPreferences: [],
      theme: 'dark',
      language: 'en',
      sensitiveContent: 'moderate',
      abigailTone: 'concise',
    },
    billingPurchases: {
      subscriptions: [],
      paymentMethods: [],
      billingHistory: [],
      receipts: [],
      autoRenewEnabled: true,
    },
    devicesSessions: {
      activeSessions: [],
      deviceList: [],
      loginHistory: [],
    },
    abigailPersonalization: {
      userGoals: [],
      habits: [],
      interests: [],
      learningStyle: '',
      memorySummary: 'No summary yet.',
    },
    accountManagement: {
      legalAgreementsAcceptedAt: ts,
      ageVerificationStatus: 'pending',
    },
    updatedAt: ts,
  };
}

export default function MeSettingsScreen() {
  const { user, setUser, logout } = useAuth();
  const [settings, setSettings] = useState<UserSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!user) return;
    const currentUser = user;
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const res = await usersApi.getMySettings();
        if (!cancelled) setSettings(res.settings);
      } catch {
        if (!cancelled) {
          setSettings(buildDefaultSettings(currentUser));
          setError('Settings service unavailable; showing local defaults.');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [user]);

  const current = useMemo(() => {
    if (!settings && user) return buildDefaultSettings(user);
    return settings;
  }, [settings, user]);

  async function patchSettings(patch: Partial<UserSettings>) {
    const prior = current;
    if (!prior) return;

    setBusy(true);
    setStatusMsg(null);
    setError(null);

    try {
      const res = await usersApi.updateMySettings(patch);
      setSettings(res.settings);
      setStatusMsg('Saved.');
    } catch (err) {
      setError((err as Error).message || 'Unable to save settings.');
      throw err;
    } finally {
      setBusy(false);
    }
  }

  async function saveIdentityField(field: 'displayName' | 'username' | 'bio' | 'avatarUrl', value: string) {
    if (!user || !current) return;

    const body = field === 'avatarUrl'
      ? { avatarUrl: value || null }
      : { [field]: value };

    const res = await usersApi.updateMe(body as { username?: string; displayName?: string; bio?: string; avatarUrl?: string | null; creatorKeyId?: string });
    setUser(res.user);

    await patchSettings({
      personalInformation: {
        ...current.personalInformation,
        displayName: field === 'displayName' ? value : current.personalInformation.displayName,
        username: field === 'username' ? value : current.personalInformation.username,
        bio: field === 'bio' ? value : current.personalInformation.bio,
        profilePhoto: field === 'avatarUrl' ? value : current.personalInformation.profilePhoto,
      },
    });
  }

  async function savePhotoUpload(kind: 'profile' | 'banner', file: File) {
    if (!current) return;
    const dataUrl = await readFileAsDataUrl(file);

    if (kind === 'profile') {
      await saveIdentityField('avatarUrl', dataUrl);
      return;
    }

    await patchSettings({
      personalInformation: {
        ...current.personalInformation,
        bannerPhoto: dataUrl,
      },
    });
  }

  async function addUserToList(listType: 'blocked' | 'muted') {
    if (!current) return;
    const raw = window.prompt(`Enter username or account id to ${listType === 'blocked' ? 'block' : 'mute'}:`);
    if (!raw) return;

    const identifier = normalizeIdentifier(raw);
    if (!identifier) return;

    const existing = listType === 'blocked'
      ? current.privacySafety.blockedUsers
      : current.privacySafety.mutedUsers;
    if (existing.some((item) => item.toLowerCase() === identifier.toLowerCase())) {
      setStatusMsg(`${identifier} is already in the ${listType} list.`);
      return;
    }

    const next = [...existing, identifier];
    await patchSettings({
      privacySafety: {
        ...current.privacySafety,
        blockedUsers: listType === 'blocked' ? next : current.privacySafety.blockedUsers,
        mutedUsers: listType === 'muted' ? next : current.privacySafety.mutedUsers,
      },
    });
  }

  async function removeUserFromList(listType: 'blocked' | 'muted', identifier: string) {
    if (!current) return;
    const existing = listType === 'blocked'
      ? current.privacySafety.blockedUsers
      : current.privacySafety.mutedUsers;
    const next = existing.filter((item) => item !== identifier);

    await patchSettings({
      privacySafety: {
        ...current.privacySafety,
        blockedUsers: listType === 'blocked' ? next : current.privacySafety.blockedUsers,
        mutedUsers: listType === 'muted' ? next : current.privacySafety.mutedUsers,
      },
    });
  }

  async function toggleContentPreference(item: string) {
    if (!current) return;
    const hasItem = current.preferences.contentPreferences.includes(item);
    const next = hasItem
      ? current.preferences.contentPreferences.filter((value) => value !== item)
      : [...current.preferences.contentPreferences, item];
    await patchSettings({
      preferences: {
        ...current.preferences,
        contentPreferences: next,
      },
    });
  }

  async function runExportData() {
    try {
      const payload = await usersApi.exportMySettings();
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `origin-settings-export-${Date.now()}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
      setStatusMsg('Data export downloaded.');
    } catch (err) {
      setError((err as Error).message || 'Export failed.');
    }
  }

  async function runDeleteData() {
    const ok = window.confirm('Delete private settings data from this app store? This cannot be undone.');
    if (!ok || !user) return;

    try {
      await usersApi.deleteMySettings();
      setSettings(buildDefaultSettings(user));
      setStatusMsg('Private settings data deleted.');
    } catch (err) {
      setError((err as Error).message || 'Delete failed.');
    }
  }

  async function runAbigailMemorySummary() {
    if (!user) return;
    try {
      const snapshot = await abigailApi.memorySnapshot({ userId: user.id });
      const context = await abigailApi.memoryContext({ userId: user.id, limit: 8 });
      await patchSettings({
        abigailPersonalization: {
          ...current!.abigailPersonalization,
          memorySummary: `Events: ${snapshot.events.length}, context signals: ${context.bundle.length}`,
        },
      });
    } catch (err) {
      setError((err as Error).message || 'Unable to fetch memory summary.');
    }
  }

  async function runForgetSpecificMemory() {
    if (!user) return;
    const memoryType = window.prompt('Enter Abigail memory type to forget (goal, preference, habit, trait, fact, reaction):', 'goal');
    if (!memoryType) return;
    try {
      await abigailApi.forgetMemory({ userId: user.id, type: memoryType, hardDelete: false });
      setStatusMsg(`Requested forgetting memories of type: ${memoryType}`);
    } catch (err) {
      setError((err as Error).message || 'Unable to forget specific memory type.');
    }
  }

  async function runForgetEverything() {
    if (!user) return;
    const ok = window.confirm('Forget all Abigail memories for your account?');
    if (!ok) return;
    try {
      await abigailApi.forgetMemory({ userId: user.id, hardDelete: false, anonymize: true });
      await patchSettings({
        abigailPersonalization: {
          ...current!.abigailPersonalization,
          memorySummary: 'Memory reset requested.',
        },
      });
      setStatusMsg('Abigail memory reset requested.');
    } catch (err) {
      setError((err as Error).message || 'Unable to reset Abigail memory.');
    }
  }

  async function teachAbigail() {
    if (!user) return;
    const note = window.prompt('Teach Abigail something new:');
    if (!note?.trim()) return;
    try {
      await abigailApi.updateMemory({
        userId: user.id,
        events: [
          {
            id: `manual-${Date.now()}`,
            type: 'note',
            title: 'User teaching note',
            detail: note.trim(),
            createdAt: new Date().toISOString(),
          },
        ],
      });
      setStatusMsg('Abigail note saved.');
    } catch (err) {
      setError((err as Error).message || 'Unable to teach Abigail right now.');
    }
  }

  async function correctAbigail() {
    if (!user) return;
    const correction = window.prompt('Enter correction for Abigail:');
    if (!correction?.trim()) return;
    try {
      await abigailApi.updateMemory({
        userId: user.id,
        events: [
          {
            id: `correction-${Date.now()}`,
            type: 'note',
            title: 'User correction',
            detail: correction.trim(),
            createdAt: new Date().toISOString(),
          },
        ],
      });
      setStatusMsg('Correction submitted to Abigail memory.');
    } catch (err) {
      setError((err as Error).message || 'Unable to submit correction.');
    }
  }

  async function resetAbigailUnderstanding() {
    if (!user) return;
    const ok = window.confirm('Reset Abigail understanding for your account?');
    if (!ok) return;
    try {
      await abigailApi.forgetMemory({ userId: user.id, anonymize: true, hardDelete: false });
      setStatusMsg('Requested reset of Abigail understanding.');
    } catch (err) {
      setError((err as Error).message || 'Unable to reset Abigail understanding.');
    }
  }

  async function changePassword() {
    const currentPassword = window.prompt('Current password:');
    if (!currentPassword) return;
    const newPassword = window.prompt('New password (8+ chars):');
    if (!newPassword) return;
    try {
      await usersApi.changePassword({ currentPassword, newPassword });
      setStatusMsg('Password updated.');
    } catch (err) {
      setError((err as Error).message || 'Unable to change password.');
    }
  }

  if (!user) {
    return <main style={{ maxWidth: 980, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>Sign in to open your settings hub.</main>;
  }

  if (loading || !current) {
    return <main style={{ maxWidth: 980, margin: '0 auto', color: '#e5e7eb', padding: 12 }}>Loading your settings…</main>;
  }

  return (
    <main style={{ maxWidth: 1040, margin: '0 auto', color: '#e5e7eb', padding: 12, display: 'grid', gap: 12 }}>
      <header style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 12 }}>
        <h2 style={{ margin: '0 0 6px' }}>My Settings Hub</h2>
        <p style={{ margin: 0, color: '#94a3b8' }}>
          Private controls for identity, privacy, preferences, security, billing, devices, and Abigail personalization.
        </p>
        <p style={{ margin: '8px 0 0', color: '#94a3b8', fontSize: 12 }}>
          Last updated: {safeDate(current.updatedAt)}
        </p>
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          <Link to="/abigail" style={{ color: '#93c5fd' }}>Open Abigail</Link>
          <Link to="/billing" style={{ color: '#93c5fd' }}>Open Billing page</Link>
          <button type="button" onClick={logout}>Log out</button>
        </div>
      </header>

      {statusMsg ? <p style={{ margin: 0, color: '#86efac' }}>{statusMsg}</p> : null}
      {error ? <p style={{ margin: 0, color: '#fca5a5' }}>{error}</p> : null}

      <SettingsSectionCard title="1. Personal Information" description="Identity and contact details used in your private account settings.">
        <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
          <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 10 }}>
            <h4 style={{ margin: 0 }}>Identity</h4>
            <EditableFieldRow label="Display name" value={current.personalInformation.displayName} onSave={(value) => saveIdentityField('displayName', value)} />
            <EditableFieldRow label="Username" value={current.personalInformation.username} onSave={(value) => saveIdentityField('username', value)} />
            <EditableFieldRow
              label="Pronouns"
              value={current.personalInformation.pronouns}
              type="select"
              options={PRONOUN_OPTIONS}
              onSave={(value) => patchSettings({ personalInformation: { ...current.personalInformation, pronouns: value } })}
            />
            <EditableFieldRow label="Birthday" value={current.personalInformation.birthday} type="date" privateLabel onSave={(value) => patchSettings({ personalInformation: { ...current.personalInformation, birthday: value } })} />
          </div>

          <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 10 }}>
            <h4 style={{ margin: 0 }}>Profile</h4>
            <EditableFieldRow label="Bio" value={current.personalInformation.bio} type="textarea" onSave={(value) => saveIdentityField('bio', value)} />
            <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, display: 'grid', gap: 8 }}>
              <strong>Profile photo</strong>
              <p style={{ margin: 0, color: '#94a3b8', fontSize: 12 }}>Upload image instead of pasting a URL.</p>
              <input
                type="file"
                accept="image/*"
                onChange={(event) => {
                  const selected = event.target.files?.[0];
                  if (!selected) return;
                  void savePhotoUpload('profile', selected);
                  event.currentTarget.value = '';
                }}
              />
              <button
                type="button"
                onClick={() => void saveIdentityField('avatarUrl', '')}
                style={{ width: 'fit-content', background: 'transparent', border: 'none', color: '#93c5fd', padding: 0, cursor: 'pointer', textDecoration: 'underline' }}
              >
                Remove photo
              </button>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, display: 'grid', gap: 8 }}>
              <strong>Banner photo</strong>
              <p style={{ margin: 0, color: '#94a3b8', fontSize: 12 }}>Upload supported. Banner render is staged for profile header rollout.</p>
              <input
                type="file"
                accept="image/*"
                onChange={(event) => {
                  const selected = event.target.files?.[0];
                  if (!selected) return;
                  void savePhotoUpload('banner', selected);
                  event.currentTarget.value = '';
                }}
              />
              <button
                type="button"
                onClick={() => void patchSettings({ personalInformation: { ...current.personalInformation, bannerPhoto: '' } })}
                style={{ width: 'fit-content', background: 'transparent', border: 'none', color: '#93c5fd', padding: 0, cursor: 'pointer', textDecoration: 'underline' }}
              >
                Remove banner
              </button>
            </div>
            <EditableFieldRow label="Location" value={current.personalInformation.location} onSave={(value) => patchSettings({ personalInformation: { ...current.personalInformation, location: value } })} />
          </div>

          <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 10 }}>
            <h4 style={{ margin: 0 }}>Contact</h4>
            <EditableFieldRow label="Contact email" value={current.personalInformation.contactEmail} type="email" privateLabel onSave={(value) => patchSettings({ personalInformation: { ...current.personalInformation, contactEmail: value } })} />
            <EditableFieldRow label="Phone number" value={current.personalInformation.phoneNumber} type="tel" onSave={(value) => patchSettings({ personalInformation: { ...current.personalInformation, phoneNumber: value } })} />
          </div>
        </div>
      </SettingsSectionCard>

      <SettingsSectionCard title="2. Privacy & Safety" description="Control audience, direct messages, account protections, and memory privacy.">
        <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
          <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 10 }}>
            <h4 style={{ margin: 0 }}>Audience & Messaging</h4>
            <EditableFieldRow
              label="Who can message me"
              value={current.privacySafety.whoCanMessageMe}
              type="select"
              options={[
                { label: 'Everyone', value: 'everyone' },
                { label: 'Friends', value: 'friends' },
                { label: 'Followers', value: 'followers' },
                { label: 'No one', value: 'no_one' },
              ]}
              onSave={(value) => patchSettings({ privacySafety: { ...current.privacySafety, whoCanMessageMe: value as 'everyone' | 'friends' | 'followers' | 'no_one' } })}
            />
            <EditableFieldRow
              label="Who can see my posts"
              value={current.privacySafety.whoCanSeeMyPosts}
              type="select"
              options={[
                { label: 'Public', value: 'public' },
                { label: 'Followers', value: 'followers' },
                { label: 'Private', value: 'private' },
              ]}
              onSave={(value) => patchSettings({ privacySafety: { ...current.privacySafety, whoCanSeeMyPosts: value as 'public' | 'followers' | 'private' } })}
            />
          </div>

          <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 10 }}>
            <h4 style={{ margin: 0 }}>Safety Controls</h4>
            <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, display: 'grid', gap: 8 }}>
              <strong>Blocked users</strong>
              <p style={{ margin: 0, color: '#94a3b8', fontSize: 13 }}>{current.privacySafety.blockedUsers.length} accounts blocked</p>
              {current.privacySafety.blockedUsers.length === 0 ? (
                <p style={{ margin: 0, color: '#cbd5e1', fontSize: 12 }}>No blocked accounts.</p>
              ) : (
                <div style={{ display: 'grid', gap: 6 }}>
                  {current.privacySafety.blockedUsers.map((entry) => (
                    <div key={`blocked-${entry}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                      <span style={{ fontSize: 13, color: '#e2e8f0' }}>{entry}</span>
                      <button
                        type="button"
                        onClick={() => void removeUserFromList('blocked', entry)}
                        style={{ background: 'transparent', border: 'none', color: '#93c5fd', padding: 0, cursor: 'pointer', textDecoration: 'underline', fontSize: 12 }}
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
              )}
              <button
                type="button"
                onClick={() => void addUserToList('blocked')}
                style={{ width: 'fit-content', background: 'transparent', border: 'none', color: '#93c5fd', padding: 0, cursor: 'pointer', textDecoration: 'underline' }}
              >
                Block someone
              </button>
            </div>
            <div style={{ border: '1px solid #334155', borderRadius: 8, padding: 10, display: 'grid', gap: 8 }}>
              <strong>Muted users</strong>
              <p style={{ margin: 0, color: '#94a3b8', fontSize: 13 }}>{current.privacySafety.mutedUsers.length} accounts muted</p>
              {current.privacySafety.mutedUsers.length === 0 ? (
                <p style={{ margin: 0, color: '#cbd5e1', fontSize: 12 }}>No muted accounts.</p>
              ) : (
                <div style={{ display: 'grid', gap: 6 }}>
                  {current.privacySafety.mutedUsers.map((entry) => (
                    <div key={`muted-${entry}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                      <span style={{ fontSize: 13, color: '#e2e8f0' }}>{entry}</span>
                      <button
                        type="button"
                        onClick={() => void removeUserFromList('muted', entry)}
                        style={{ background: 'transparent', border: 'none', color: '#93c5fd', padding: 0, cursor: 'pointer', textDecoration: 'underline', fontSize: 12 }}
                      >
                        Remove
                      </button>
                    </div>
                  ))}
                </div>
              )}
              <button
                type="button"
                onClick={() => void addUserToList('muted')}
                style={{ width: 'fit-content', background: 'transparent', border: 'none', color: '#93c5fd', padding: 0, cursor: 'pointer', textDecoration: 'underline' }}
              >
                Mute someone
              </button>
            </div>
          </div>

          <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 10 }}>
            <h4 style={{ margin: 0 }}>Account Protection</h4>
            <EditableFieldRow
              label="Two-factor authentication"
              value={current.privacySafety.twoFactorAuthEnabled ? 'enabled' : 'disabled'}
              type="select"
              options={[{ label: 'Enabled', value: 'enabled' }, { label: 'Disabled', value: 'disabled' }]}
              onSave={(value) => patchSettings({ privacySafety: { ...current.privacySafety, twoFactorAuthEnabled: value === 'enabled' } })}
            />
            <EditableFieldRow
              label="Login alerts"
              value={current.privacySafety.loginAlertsEnabled ? 'enabled' : 'disabled'}
              type="select"
              options={[{ label: 'Enabled', value: 'enabled' }, { label: 'Disabled', value: 'disabled' }]}
              onSave={(value) => patchSettings({ privacySafety: { ...current.privacySafety, loginAlertsEnabled: value === 'enabled' } })}
            />
          </div>

          <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 10 }}>
            <h4 style={{ margin: 0 }}>Data Controls</h4>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button type="button" onClick={() => void runExportData()} disabled={busy}>Data export</button>
              <button type="button" onClick={() => void runDeleteData()} disabled={busy}>Data deletion</button>
            </div>
            <p style={{ margin: 0, color: '#94a3b8', fontSize: 12 }}>Export creates a local JSON snapshot. Deletion clears private settings data.</p>
          </div>
        </div>

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 8, marginTop: 10 }}>
          <strong>Abigail memory controls</strong>
          <EditableFieldRow
            label="Pause memory collection"
            value={current.privacySafety.pauseAbigailMemoryCollection ? 'enabled' : 'disabled'}
            type="select"
            options={[{ label: 'Enabled', value: 'enabled' }, { label: 'Disabled', value: 'disabled' }]}
            onSave={(value) => patchSettings({ privacySafety: { ...current.privacySafety, pauseAbigailMemoryCollection: value === 'enabled' } })}
          />
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button type="button" onClick={() => void runAbigailMemorySummary()}>View memory summary</button>
            <button type="button" onClick={() => void runForgetSpecificMemory()}>Forget specific memories</button>
            <button type="button" onClick={() => void runForgetEverything()}>Forget everything</button>
          </div>
        </div>
      </SettingsSectionCard>

      <SettingsSectionCard title="3. Preferences" description="Tune notifications, feed behavior, content preferences, and Abigail tone.">
        <EditableFieldRow
          label="Notification settings"
          value={current.preferences.notificationMode}
          type="select"
          options={[{ label: 'All', value: 'all' }, { label: 'Important', value: 'important' }, { label: 'Minimal', value: 'minimal' }]}
          onSave={(value) => patchSettings({ preferences: { ...current.preferences, notificationMode: value as 'all' | 'important' | 'minimal' } })}
        />
        <EditableFieldRow
          label="Feed tuning"
          value={current.preferences.feedTuning}
          type="select"
          options={[
            { label: 'Balanced', value: 'balanced' },
            { label: 'Following first', value: 'following_first' },
            { label: 'Discovery first', value: 'discovery_first' },
          ]}
          onSave={(value) => patchSettings({ preferences: { ...current.preferences, feedTuning: value as 'balanced' | 'following_first' | 'discovery_first' } })}
        />
        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'grid', gap: 8 }}>
          <strong>Content preferences</strong>
          <p style={{ margin: 0, color: '#94a3b8', fontSize: 13 }}>Pick topics to tune recommendations.</p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {CONTENT_PREFERENCE_OPTIONS.map((item) => {
              const selected = current.preferences.contentPreferences.includes(item);
              return (
                <button
                  key={item}
                  type="button"
                  onClick={() => void toggleContentPreference(item)}
                  style={{
                    borderRadius: 999,
                    border: selected ? '1px solid #60a5fa' : '1px solid #334155',
                    background: selected ? '#1e3a8a' : '#020617',
                    color: '#e5e7eb',
                    padding: '4px 10px',
                    cursor: 'pointer',
                  }}
                >
                  {item}
                </button>
              );
            })}
          </div>
        </div>
        <EditableFieldRow
          label="Theme"
          value={current.preferences.theme}
          type="select"
          options={[{ label: 'Dark', value: 'dark' }, { label: 'Light', value: 'light' }]}
          onSave={(value) => patchSettings({ preferences: { ...current.preferences, theme: value as 'dark' | 'light' } })}
        />
        <EditableFieldRow label="Language" value={current.preferences.language} onSave={(value) => patchSettings({ preferences: { ...current.preferences, language: value } })} />
        <EditableFieldRow
          label="Sensitive content settings"
          value={current.preferences.sensitiveContent}
          type="select"
          options={[{ label: 'Strict', value: 'strict' }, { label: 'Moderate', value: 'moderate' }, { label: 'Permissive', value: 'permissive' }]}
          onSave={(value) => patchSettings({ preferences: { ...current.preferences, sensitiveContent: value as 'strict' | 'moderate' | 'permissive' } })}
        />
        <EditableFieldRow
          label="Abigail tone preferences"
          value={current.preferences.abigailTone}
          type="select"
          options={[
            { label: 'Professional', value: 'professional' },
            { label: 'Casual', value: 'casual' },
            { label: 'Concise', value: 'concise' },
            { label: 'Detailed', value: 'detailed' },
          ]}
          onSave={(value) => patchSettings({ preferences: { ...current.preferences, abigailTone: value as 'professional' | 'casual' | 'concise' | 'detailed' } })}
        />
      </SettingsSectionCard>

      <SettingsSectionCard title="4. Billing & Purchases" description="Review subscriptions, payments, receipts, and renewal behavior.">
        <EditableFieldRow
          label="Manage renewals"
          value={current.billingPurchases.autoRenewEnabled ? 'enabled' : 'disabled'}
          type="select"
          options={[{ label: 'Enabled', value: 'enabled' }, { label: 'Disabled', value: 'disabled' }]}
          onSave={(value) => patchSettings({ billingPurchases: { ...current.billingPurchases, autoRenewEnabled: value === 'enabled' } })}
        />

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
          <strong>Subscriptions you pay for</strong>
          {current.billingPurchases.subscriptions.length === 0 ? <p style={{ margin: '8px 0 0', color: '#94a3b8' }}>No active subscriptions.</p> : (
            <ul style={{ margin: '8px 0 0', paddingLeft: 16 }}>
              {current.billingPurchases.subscriptions.map((item) => (
                <li key={item.id}>{item.name} • {item.status} {item.renewalAt ? `• renews ${safeDate(item.renewalAt)}` : ''}</li>
              ))}
            </ul>
          )}
        </div>

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
          <strong>Payment methods</strong>
          {current.billingPurchases.paymentMethods.length === 0 ? <p style={{ margin: '8px 0 0', color: '#94a3b8' }}>No saved payment methods.</p> : (
            <ul style={{ margin: '8px 0 0', paddingLeft: 16 }}>
              {current.billingPurchases.paymentMethods.map((item) => (
                <li key={item.id}>{item.brand.toUpperCase()} •••• {item.last4} • {item.expMonth}/{item.expYear}</li>
              ))}
            </ul>
          )}
        </div>

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
          <strong>Billing history</strong>
          {current.billingPurchases.billingHistory.length === 0 ? <p style={{ margin: '8px 0 0', color: '#94a3b8' }}>No billing history yet.</p> : (
            <ul style={{ margin: '8px 0 0', paddingLeft: 16 }}>
              {current.billingPurchases.billingHistory.map((item) => (
                <li key={item.id}>${item.amountUsd.toFixed(2)} • {item.description} • {safeDate(item.createdAt)}</li>
              ))}
            </ul>
          )}
        </div>

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
          <strong>Receipts</strong>
          {current.billingPurchases.receipts.length === 0 ? <p style={{ margin: '8px 0 0', color: '#94a3b8' }}>No receipts yet.</p> : (
            <ul style={{ margin: '8px 0 0', paddingLeft: 16 }}>
              {current.billingPurchases.receipts.map((item) => (
                <li key={item.id}><a href={item.url} target="_blank" rel="noreferrer" style={{ color: '#93c5fd' }}>{item.title}</a> • {safeDate(item.createdAt)}</li>
              ))}
            </ul>
          )}
        </div>
      </SettingsSectionCard>

      <SettingsSectionCard title="5. Devices & Sessions" description="Inspect active sessions, known devices, and login history.">
        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
          <strong>Active sessions</strong>
          {current.devicesSessions.activeSessions.length === 0 ? <p style={{ margin: '8px 0 0', color: '#94a3b8' }}>No active sessions listed.</p> : (
            <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
              {current.devicesSessions.activeSessions.map((session) => (
                <div key={session.id} style={{ border: '1px solid #334155', borderRadius: 8, padding: 8 }}>
                  <p style={{ margin: 0 }}>{session.deviceName} • {session.location} • {session.ipAddress}</p>
                  <p style={{ margin: '4px 0 0', fontSize: 12, color: '#94a3b8' }}>Last seen: {safeDate(session.lastSeenAt)}</p>
                  {!session.current ? (
                    <button type="button" onClick={() => void usersApi.revokeMySession(session.id).then((res) => setSettings(res.settings))} style={{ marginTop: 6 }}>
                      Revoke session
                    </button>
                  ) : <p style={{ margin: '6px 0 0', fontSize: 12, color: '#86efac' }}>Current session</p>}
                </div>
              ))}
            </div>
          )}
        </div>

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
          <strong>Device list</strong>
          {current.devicesSessions.deviceList.length === 0 ? <p style={{ margin: '8px 0 0', color: '#94a3b8' }}>No devices listed.</p> : (
            <ul style={{ margin: '8px 0 0', paddingLeft: 16 }}>
              {current.devicesSessions.deviceList.map((item) => (
                <li key={item.id}>{item.deviceName} • {item.location} • {safeDate(item.lastSeenAt)}</li>
              ))}
            </ul>
          )}
        </div>

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
          <strong>Login history</strong>
          {current.devicesSessions.loginHistory.length === 0 ? <p style={{ margin: '8px 0 0', color: '#94a3b8' }}>No login history yet.</p> : (
            <ul style={{ margin: '8px 0 0', paddingLeft: 16 }}>
              {current.devicesSessions.loginHistory.map((item) => (
                <li key={item.id}>{item.deviceName} • {item.location} • {item.ipAddress} • {safeDate(item.createdAt)}</li>
              ))}
            </ul>
          )}
        </div>
      </SettingsSectionCard>

      <SettingsSectionCard title="6. Abigail Personalization Panel" description="Manage goals, habits, interests, and understanding quality.">
        <EditableFieldRow label="User goals" value={listToCsv(current.abigailPersonalization.userGoals)} type="textarea" onSave={(value) => patchSettings({ abigailPersonalization: { ...current.abigailPersonalization, userGoals: csvToList(value) } })} />
        <EditableFieldRow label="Habits" value={listToCsv(current.abigailPersonalization.habits)} type="textarea" onSave={(value) => patchSettings({ abigailPersonalization: { ...current.abigailPersonalization, habits: csvToList(value) } })} />
        <EditableFieldRow label="Interests" value={listToCsv(current.abigailPersonalization.interests)} type="textarea" onSave={(value) => patchSettings({ abigailPersonalization: { ...current.abigailPersonalization, interests: csvToList(value) } })} />
        <EditableFieldRow label="Learning style" value={current.abigailPersonalization.learningStyle} onSave={(value) => patchSettings({ abigailPersonalization: { ...current.abigailPersonalization, learningStyle: value } })} />
        <EditableFieldRow label="Memory summary" value={current.abigailPersonalization.memorySummary} type="textarea" onSave={(value) => patchSettings({ abigailPersonalization: { ...current.abigailPersonalization, memorySummary: value } })} />

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => void teachAbigail()}>Teach Abigail something new</button>
          <button type="button" onClick={() => void correctAbigail()}>Correct Abigail</button>
          <button type="button" onClick={() => void resetAbigailUnderstanding()}>Reset Abigail’s understanding</button>
        </div>
      </SettingsSectionCard>

      <SettingsSectionCard title="7. Account Management" description="Security-critical actions and legal/account status controls.">
        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => void changePassword()}>Change password</button>
          <button
            type="button"
            onClick={() => {
              const nextEmail = window.prompt('Enter new contact email:', current.personalInformation.contactEmail);
              if (!nextEmail) return;
              void patchSettings({ personalInformation: { ...current.personalInformation, contactEmail: nextEmail.trim() } });
            }}
          >
            Change email
          </button>
          <button type="button" onClick={() => void runDeleteData()}>Delete account data</button>
          <button type="button" onClick={() => void runExportData()}>Export account</button>
        </div>

        <EditableFieldRow
          label="Age verification status"
          value={current.accountManagement.ageVerificationStatus}
          type="select"
          options={[{ label: 'Unverified', value: 'unverified' }, { label: 'Pending', value: 'pending' }, { label: 'Verified', value: 'verified' }]}
          onSave={(value) => patchSettings({ accountManagement: { ...current.accountManagement, ageVerificationStatus: value as 'unverified' | 'pending' | 'verified' } })}
        />

        <div style={{ border: '1px solid #1f2937', borderRadius: 10, background: '#0f172a', padding: 10 }}>
          <strong>Legal agreements</strong>
          <p style={{ margin: '6px 0 0', color: '#cbd5e1' }}>Accepted at: {safeDate(current.accountManagement.legalAgreementsAcceptedAt)}</p>
          <p style={{ margin: '6px 0 0' }}>
            <Link to="/terms" style={{ color: '#93c5fd' }}>View legal agreements</Link>
          </p>
        </div>
      </SettingsSectionCard>
    </main>
  );
}
