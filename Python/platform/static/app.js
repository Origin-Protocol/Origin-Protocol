/* Origin Protocol – Creator Dashboard App */
'use strict';

(function () {
  // ── State ──────────────────────────────────────────────────────────────
  const state = {
    theme: localStorage.getItem('op-theme') || 'light',
    screen: 'overview',
  };

  // ── DOM refs ────────────────────────────────────────────────────────────
  const html         = document.documentElement;
  const sidebar      = document.getElementById('sidebar');
  const overlay      = document.getElementById('overlay');
  const menuToggle   = document.getElementById('menuToggle');
  const sidebarClose = document.getElementById('sidebarClose');
  const themeToggle  = document.getElementById('themeToggle');
  const topbarTitle  = document.getElementById('topbarTitle');
  const apiStatus    = document.getElementById('apiStatus');

  // ── Theme ───────────────────────────────────────────────────────────────
  function applyTheme(t) {
    state.theme = t;
    html.setAttribute('data-theme', t);
    localStorage.setItem('op-theme', t);
    themeToggle.querySelector('.theme-icon').textContent = t === 'dark' ? '☾' : '☀';
  }

  applyTheme(state.theme);

  themeToggle.addEventListener('click', function () {
    applyTheme(state.theme === 'dark' ? 'light' : 'dark');
  });

  // ── Sidebar toggle ──────────────────────────────────────────────────────
  function openSidebar() {
    sidebar.classList.add('open');
    overlay.classList.add('visible');
    document.body.style.overflow = 'hidden';
  }

  function closeSidebar() {
    sidebar.classList.remove('open');
    overlay.classList.remove('visible');
    document.body.style.overflow = '';
  }

  menuToggle.addEventListener('click', openSidebar);
  sidebarClose.addEventListener('click', closeSidebar);
  overlay.addEventListener('click', closeSidebar);

  // ── Navigation ──────────────────────────────────────────────────────────
  const screenTitles = {
    overview:   'Overview',
    verify:     'Verify Content',
    keys:       'Key Status',
    revocation: 'Revocation Check',
    policy:     'Platform Policy',
  };

  function navigate(screen) {
    // Deactivate current
    document.querySelectorAll('.nav-item').forEach(function (el) {
      el.classList.toggle('active', el.dataset.screen === screen);
    });

    // Hide all screens
    document.querySelectorAll('.screen').forEach(function (el) {
      el.classList.add('hidden');
    });

    // Show target screen
    const el = document.getElementById('screen-' + screen);
    if (el) el.classList.remove('hidden');

    state.screen = screen;
    topbarTitle.textContent = screenTitles[screen] || screen;
    closeSidebar();

    // Lazy loads
    if (screen === 'overview') loadOverview();
  }

  document.querySelectorAll('.nav-item').forEach(function (item) {
    item.addEventListener('click', function () { navigate(item.dataset.screen); });
  });

  // ── API helpers ─────────────────────────────────────────────────────────
  async function api(method, path, body) {
    const opts = {
      method: method,
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    if (!res.ok) {
      let detail = '';
      try { detail = (await res.json()).detail || ''; } catch (_) {}
      throw new Error('HTTP ' + res.status + (detail ? ': ' + detail : ''));
    }
    return res.json();
  }

  // ── API Status ──────────────────────────────────────────────────────────
  async function checkApiStatus() {
    const dot = apiStatus.querySelector('.status-dot');
    const lbl = apiStatus.querySelector('.status-label');
    try {
      await fetch('/v1/ledger/platform-policy?platform_id=', {
        signal: AbortSignal.timeout(3000),
      });
      dot.className = 'status-dot online';
      lbl.textContent = 'API';
    } catch (_) {
      dot.className = 'status-dot offline';
      lbl.textContent = 'Offline';
    }
  }

  checkApiStatus();

  // ── Overview ────────────────────────────────────────────────────────────
  async function loadPolicySummary() {
    const container = document.getElementById('policy-summary-content');
    container.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Loading policy…</span></div>';
    try {
      const data = await api('GET', '/v1/ledger/platform-policy');
      container.innerHTML = renderPolicyContent(data);
      // Update stat card
      const profileName = (data.policy && data.policy.profile) || '—';
      const statEl = document.getElementById('stat-platforms');
      if (statEl) statEl.textContent = profileName;

      // Governance node count
      const statNodes = document.getElementById('stat-nodes');
      if (statNodes) {
        const nodes = (data.governance && data.governance.node_endpoints) || [];
        statNodes.textContent = nodes.length || '—';
      }
    } catch (err) {
      container.innerHTML = '<div class="error-banner">Could not load policy: ' + escHtml(err.message) + '</div>';
    }
  }

  function loadOverview() {
    loadPolicySummary();
    document.getElementById('stat-verified').textContent = '—';
    document.getElementById('stat-keys').textContent = '—';
  }

  // Expose for inline onclick
  window.app = { navigate: navigate, loadPolicySummary: loadPolicySummary };

  // ── Verify Content ──────────────────────────────────────────────────────
  const verifyForm = document.getElementById('verifyForm');
  const verifyResult = document.getElementById('verifyResult');

  verifyForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    const btn = document.getElementById('verifySubmit');
    btn.disabled = true;
    btn.textContent = 'Verifying…';
    verifyResult.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Verifying…</span></div>';

    const body = {
      creator_id:   verifyForm.elements.creator_id.value.trim(),
      key_id:       verifyForm.elements.key_id.value.trim(),
      asset_id:     verifyForm.elements.asset_id.value.trim(),
      content_hash: verifyForm.elements.content_hash.value.trim(),
      platform_id:  verifyForm.elements.platform_id.value.trim(),
    };

    try {
      const data = await api('POST', '/v1/ledger/verify', body);
      verifyResult.innerHTML = renderVerifyResult(data);
    } catch (err) {
      verifyResult.innerHTML = '<div class="error-banner">' + escHtml(err.message) + '</div>';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Verify Content';
    }
  });

  document.getElementById('verifyReset').addEventListener('click', function () {
    verifyForm.reset();
    verifyResult.innerHTML = '<div class="empty-state"><span class="empty-icon">✓</span><p>Submit the form to see the verification result.</p></div>';
  });

  // ── Key Status ──────────────────────────────────────────────────────────
  const keyForm   = document.getElementById('keyForm');
  const keyResult = document.getElementById('keyResult');

  keyForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    const creator_id = document.getElementById('k-creator-id').value.trim();
    const key_id     = document.getElementById('k-key-id').value.trim();
    keyResult.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Checking key…</span></div>';

    try {
      const data = await api('GET', '/v1/ledger/key-status?creator_id=' + encodeURIComponent(creator_id) + '&key_id=' + encodeURIComponent(key_id));
      keyResult.innerHTML = renderKeyResult(data);
    } catch (err) {
      keyResult.innerHTML = '<div class="error-banner">' + escHtml(err.message) + '</div>';
    }
  });

  document.getElementById('keyReset').addEventListener('click', function () {
    keyForm.reset();
    keyResult.innerHTML = '<div class="empty-state"><span class="empty-icon">⚿</span><p>Enter a creator ID and key ID to check the key status.</p></div>';
  });

  // ── Revocation Check ────────────────────────────────────────────────────
  const revForm   = document.getElementById('revocationForm');
  const revResult = document.getElementById('revocationResult');

  revForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    revResult.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Checking…</span></div>';

    const params = new URLSearchParams({
      creator_id:   document.getElementById('r-creator-id').value.trim(),
      key_id:       document.getElementById('r-key-id').value.trim(),
      asset_id:     document.getElementById('r-asset-id').value.trim(),
      content_hash: document.getElementById('r-content-hash').value.trim(),
      platform_id:  document.getElementById('r-platform-id').value.trim(),
    });

    try {
      const data = await api('GET', '/v1/ledger/revocation-status?' + params.toString());
      revResult.innerHTML = renderRevocationResult(data);
    } catch (err) {
      revResult.innerHTML = '<div class="error-banner">' + escHtml(err.message) + '</div>';
    }
  });

  document.getElementById('revocationReset').addEventListener('click', function () {
    revForm.reset();
    revResult.innerHTML = '<div class="empty-state"><span class="empty-icon">⊘</span><p>Enter asset details to check revocation status.</p></div>';
  });

  // ── Platform Policy ─────────────────────────────────────────────────────
  document.getElementById('policyLoad').addEventListener('click', async function () {
    const pid = document.getElementById('p-platform-id').value.trim();
    const container = document.getElementById('policyResult');
    container.innerHTML = '<div class="card card--full"><div class="loading-state"><div class="spinner"></div><span>Loading policy…</span></div></div>';

    try {
      const url = '/v1/ledger/platform-policy' + (pid ? '?platform_id=' + encodeURIComponent(pid) : '');
      const data = await api('GET', url);
      container.innerHTML = '<div class="card card--full">' + renderPolicyContent(data) + '</div>';
    } catch (err) {
      container.innerHTML = '<div class="error-banner">' + escHtml(err.message) + '</div>';
    }
  });

  // ── Renderers ───────────────────────────────────────────────────────────
  function renderVerifyResult(data) {
    const ok = data.ok;
    const cls = ok ? 'result-card--ok' : 'result-card--fail';
    const icon = ok ? '✓' : '✕';
    const titleCls = ok ? 'result-ok' : 'result-fail';
    const title = ok ? 'Verification Passed' : 'Verification Failed';
    let html = '<div class="result-card ' + cls + '">';
    html += '<div class="result-header">';
    html += '<span class="result-icon ' + titleCls + '">' + icon + '</span>';
    html += '<span class="result-title ' + titleCls + '">' + title + '</span>';
    html += '</div>';
    html += renderReasons(data.reasons);
    html += '</div>';
    return html;
  }

  function renderKeyResult(data) {
    const ok = data.ok;
    const cls = ok ? 'result-card--ok' : 'result-card--fail';
    const icon = ok ? '✓' : '✕';
    const titleCls = ok ? 'result-ok' : 'result-fail';
    const title = ok ? 'Key Active' : 'Key Inactive or Unknown';
    let html = '<div class="result-card ' + cls + '">';
    html += '<div class="result-header">';
    html += '<span class="result-icon ' + titleCls + '">' + icon + '</span>';
    html += '<span class="result-title ' + titleCls + '">' + title + '</span>';
    html += '</div>';
    if (data.key_status) {
      html += '<table class="kv-table"><tbody>';
      html += '<tr><td>Status</td><td>' + escHtml(data.key_status) + '</td></tr>';
      html += '</tbody></table>';
    }
    html += renderReasons(data.reasons);
    html += '</div>';
    return html;
  }

  function renderRevocationResult(data) {
    const revoked = data.revoked;
    const cls = revoked ? 'result-card--fail' : 'result-card--ok';
    const icon = revoked ? '⊘' : '✓';
    const titleCls = revoked ? 'result-fail' : 'result-ok';
    const title = revoked ? 'Content Revoked' : 'Not Revoked';
    let html = '<div class="result-card ' + cls + '">';
    html += '<div class="result-header">';
    html += '<span class="result-icon ' + titleCls + '">' + icon + '</span>';
    html += '<span class="result-title ' + titleCls + '">' + title + '</span>';
    html += '</div>';
    html += renderReasons(data.reasons);
    html += '</div>';
    return html;
  }

  function renderReasons(reasons) {
    if (!reasons || reasons.length === 0) return '';
    let html = '<ul class="reason-list">';
    reasons.forEach(function (r) {
      const sev = r.severity || 'low';
      const badgeCls = sev === 'critical' || sev === 'high' ? 'badge--red'
                      : sev === 'medium' ? 'badge--orange'
                      : 'badge--gray';
      html += '<li class="reason-item">';
      html += '<div style="display:flex;align-items:center;gap:8px;">';
      html += '<span class="reason-code">' + escHtml(r.code) + '</span>';
      html += '<span class="badge ' + badgeCls + '">' + escHtml(sev) + '</span>';
      html += '</div>';
      if (r.message) html += '<span class="reason-msg">' + escHtml(r.message) + '</span>';
      if (r.creator_action) html += '<span class="reason-msg" style="font-style:italic;">Action: ' + escHtml(r.creator_action) + '</span>';
      html += '</li>';
    });
    html += '</ul>';
    return html;
  }

  function renderPolicyContent(data) {
    const policy = data.policy || {};
    const governance = data.governance || null;

    let html = '<div class="policy-grid">';
    Object.entries(policy).forEach(function (_a) {
      const k = _a[0]; const v = _a[1];
      const display = typeof v === 'boolean'
        ? (v ? '<span class="badge badge--green">enabled</span>' : '<span class="badge badge--gray">disabled</span>')
        : '<span class="policy-val">' + escHtml(String(v)) + '</span>';
      html += '<div class="policy-item"><span class="policy-key">' + escHtml(k) + '</span>' + display + '</div>';
    });
    html += '</div>';

    if (governance) {
      html += '<div class="governance-section">';
      html += '<div class="governance-title">Governance</div>';

      if (governance.ledger_cid) {
        html += '<div class="policy-item" style="margin-bottom:10px;"><span class="policy-key">ledger_cid</span><span class="policy-val" style="word-break:break-all;font-family:monospace;font-size:12px;">' + escHtml(governance.ledger_cid) + '</span></div>';
      }

      const endpoints = (governance.node_endpoints || []).concat(governance.ipfs_gateways || []);
      if (endpoints.length) {
        html += '<div class="governance-title" style="margin-top:12px;">Endpoints</div>';
        html += '<div class="endpoint-list">';
        endpoints.forEach(function (ep) {
          html += '<span class="endpoint-chip">' + escHtml(ep) + '</span>';
        });
        html += '</div>';
      }
      html += '</div>';
    }

    return html;
  }

  // ── Utils ───────────────────────────────────────────────────────────────
  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ── Init ────────────────────────────────────────────────────────────────
  navigate('overview');
})();
