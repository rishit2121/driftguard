'use strict';
// DriftGuard UI. All upstream/repository text is untrusted and rendered escaped.
const $app = document.getElementById('app');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
};
const post = (path, body) => api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const short = (sha) => (sha || '').slice(0, 7);
const tierLabel = { confirmed: 'Confirmed', likely: 'Likely', candidate: 'Candidate', upgrade_risk: 'Upgrade risk',
  inventory_only: 'Inventory only', version_unverified: 'Version unverified', review: 'Needs review' };
const tier = (t) => `<span class="tier ${esc(t || 'none')}">${esc(tierLabel[t] || 'No impact')}</span>`;
const prov = (p) => `<span class="prov ${esc(p)}">${esc({ stripe: 'S', osv: 'OSV', shopify: 'Sh', semgrep: 'SG' }[p] || '?')}</span>`;
const fmtTime = (t) => (t ? new Date(t).toLocaleString() : '—');
let RUN = null; // latest run id
let FALLBACK = null;
function runBadge(run) {
  if (!run || !run.finished_at) return '';
  const ageMin = (Date.now() - new Date(run.finished_at).getTime()) / 60000;
  if (FALLBACK && run.run_id === FALLBACK) return `<span class="badge-rec" title="A previously completed genuine run, preserved as a fallback">RECORDED FALLBACK RUN · finished ${esc(fmtTime(run.finished_at))}</span>`;
  return ageMin < 10 ? `<span class="badge-live">LIVE RUN · finished ${Math.max(0, Math.round(ageMin))} min ago</span>`
    : `<span class="badge-rec">RECORDED RUN · finished ${esc(fmtTime(run.finished_at))}</span>`;
}
const langOf = (p) => ({ ts: 'TypeScript', js: 'JavaScript', py: 'Python', java: 'Java' }[(p || '').split('.').pop()] || '');
let POLL = null;

function setNav(name) {
  document.querySelectorAll('nav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === name));
}

async function services() {
  try {
    const s = await api('/api/status');
    const pill = (label, ok, title, warn) => `<span class="svc ${ok ? (warn ? 'warn' : 'ok') : 'bad'}" title="${esc(label)}: ${esc(title)}">${esc(label.split(' ')[0])}</span>`;
    const ml = s.ml;
    document.getElementById('services').innerHTML = [
      pill(`Guild ${s.guild.authenticated ? '' : '(not authorized)'}`, s.guild.ok, s.guild.detail || '', !s.guild.authenticated),
      pill(`ClickHouse ${s.clickhouse.version || ''}`, s.clickhouse.ok, s.clickhouse.host || s.clickhouse.error),
      pill(`Akash ML ${ml.ok ? '· ' + ml.deployment : ''}`, ml.ok, ml.ok ? `${ml.url} ${ml.model_version}` : ml.error, ml.ok && ml.deployment !== 'akash'),
      pill(`Semgrep ${(s.semgrep.version || '').trim()}`, s.semgrep.ok, `${s.semgrep.rules} rule files`),
      pill('GitHub', s.github.ok, s.github.full_name || s.github.error),
    ].join('');
  } catch (e) { /* header is best-effort */ }
}

async function latestRun() {
  if (!RUN) RUN = (await api('/api/investigations/latest')).run_id;
  return RUN;
}


// ------------------------------------------------------------------------------------------- Overview (demo landing)
const EXTRA_NEG = {
  'E-constant': 'Constant Log4j message (RequestAudit.java:26) must not be flagged',
  shopify: '40 live Shopify changelog entries, repo has no Shopify usage: no alerts',
  'stripe-sdk-osv': 'stripe-node 18.0.0 has no OSV advisories: no CVE alert',
};
const STAGE_LABEL = {
  repo_snapshot: 'Pinning commit', inventory: 'Reading lockfiles', source_fetch: 'Fetching official sources',
  guild_watcher: 'Guild agent investigating', ml_health: 'Connecting to Akash', doc_index: 'Embedding changes (Akash)',
  code_index: 'Embedding code (Akash)', vector_retrieval: 'ClickHouse vector search', semgrep: 'Semgrep scan',
  evidence_combine: 'Combining evidence', regression_proof: 'Running regression tests', ml_rank: 'Ranking (Akash)',
  ml_classify: 'Classifying candidates (Akash)', quarantine: 'Quarantining untrusted text',
  github_issue: 'Updating GitHub issues', pr_annotations: 'Annotating PRs',
};
const EXPECTED_STAGES = 24;

function rejectSummary(reason) {
  const m = (reason || '').match(/^tests failed: (.*)$/s);
  if (!m) return reason;
  return `${m[1].split('; ').length} tests failed`;
}
const shortPath = (p) => (p || '').split('/').slice(-2).join('/');
const prNum = (rem) => rem?.pr?.number;

function heroMetrics(inv, o) {
  const fs = inv.findings || [];
  const confirmed = fs.filter((f) => f.confidence_tier === 'confirmed');
  const review = fs.filter((f) => ['needs_review', 'unverified', 'potentially_affected', 'upgrade_risk'].includes(f.status));
  const files = new Set(confirmed.map((f) => f.path));
  const prs = new Set([o.headline, ...(o.security || [])].map((g) => prNum(g?.remediation)).filter(Boolean));
  const tile = (n, label, cls, hint) => `<div class="metric" title="${esc(hint)}"><div class="mv ${cls}">${n}</div><div class="ml">${esc(label)}</div></div>`;
  return `<div class="metrics">
    ${tile(confirmed.length, 'Confirmed findings', 'red', 'Exact Semgrep match + affected version + regression test reproduced the failure')}
    ${tile(review.length, 'Needs review', 'amber', 'Candidates, upgrade risks, unverified versions and insecure patterns: shown, never auto-fixed')}
    ${tile(files.size, 'Files affected', '', 'Distinct files with a confirmed finding')}
    ${tile(prs.size, 'Verified fixes', 'green', 'Draft PRs whose patch passed every existing and regression test')}
  </div>`;
}

function featured(run, h) {
  if (!h) return '';
  const rem = h.remediation;
  const confirmed = h.locations.filter((l) => l.tier === 'confirmed');
  const risk = h.locations.filter((l) => l.tier === 'upgrade_risk');
  const main = confirmed.find((l) => l.path.endsWith('subscription.ts')) || confirmed[0];
  const rejected = rem ? rem.attempts.filter((a) => a.verdict === 'rejected') : [];
  const accepted = rem ? rem.attempts.find((a) => a.verdict === 'accepted') : null;
  const after = rem?.after;
  return `<section class="feature">
    <div class="f-head">
      <div class="f-title">
        <span class="prov stripe">S</span>
        <div><div class="eyebrow">Breaking API change · Stripe <code>2025-03-31.basil</code></div>
          <h2>Subscription billing periods moved to subscription items</h2></div>
      </div>
      <span class="pill red">Confirmed</span>
    </div>
    <div class="steps">
      <div class="st"><div class="sn">${confirmed.length}</div><div class="sl">affected locations</div><div class="ss">exact lines via Semgrep</div></div>
      <div class="arr">→</div>
      <div class="st"><div class="sn red">${h.proof.fail}</div><div class="sl">regression failures</div><div class="ss">on unpatched code · ${h.proof.pass} other tests pass</div></div>
      <div class="arr">→</div>
      <div class="st"><div class="sn green">${after ? `${after.pass}/${after.pass + after.fail}` : '—'}</div><div class="sl">tests passing</div><div class="ss">with the verified fix</div></div>
    </div>
    ${rem ? `<div class="ba">
      ${rejected.map((a) => `<div class="ba-x"><span class="tag red">Rejected</span><code class="strike">${esc(a.candidate)}</code><span class="muted">${esc(rejectSummary(a.reason))}</span></div>`).join('')}
      ${accepted ? `<div class="ba-ok"><span class="tag green">Accepted</span><code>${esc(accepted.candidate)}</code><span class="muted">all tests pass · Semgrep re-scan clean</span></div>` : ''}
    </div>` : ''}
    ${risk.length ? `<div class="risk-note"><span class="dot amber"></span>${risk.map((l) => `<code>${esc(shortPath(l.path))}:${l.line}</code>`).join(', ')} is pinned to the older <code>acacia</code> API: <b>upgrade risk</b>, not broken today.</div>` : ''}
    <div class="actions">
      ${main ? `<a class="btn" href="#/finding/${esc(run.run_id)}/${esc(main.finding_id)}">View code</a>` : ''}
      ${h.issue ? `<a class="btn ghost" href="${esc(h.issue.url)}" target="_blank">View Issue #${h.issue.number} ↗</a>` : ''}
      ${rem ? `<a class="btn ghost" href="${esc(rem.pr.url)}" target="_blank">View PR #${rem.pr.number} ↗</a>` : ''}
      <a class="link-muted" href="${esc(h.source_url)}" target="_blank">Official Stripe changelog ↗</a>
    </div>
    <details class="more"><summary>Technical details</summary>
      <div class="more-grid">
        <div><div class="k">Affected lines</div>${h.locations.map((l) => `<div><a class="mono" href="#/finding/${esc(run.run_id)}/${esc(l.finding_id)}">${esc(l.path)}:${l.line}</a> ${l.tier === 'upgrade_risk' ? '<span class="tag amber">upgrade risk</span>' : ''}</div>`).join('')}</div>
        <div><div class="k">Failing regression tests (before fix)</div>${h.proof.failing.map((t) => `<div class="small">${esc(t)}</div>`).join('')}</div>
        <div><div class="k">Provenance</div>
          <div class="small">Scanned <code>${esc(short(run.commit_sha))}</code> · rule <code>driftguard.stripe.subscription-period-fields-removed-basil</code></div>
          ${rem ? `<div class="small">PR #${rem.pr.number} by ${esc(rem.pr.executor === 'guild' ? 'Guild remediator agent' : 'direct GitHub fallback')} · from ${esc(rem.source)}</div>` : ''}</div>
      </div>
    </details>
  </section>`;
}

function findingsTable(run, sec) {
  const rank = (g) => (g.locations.some((l) => l.tier === 'confirmed') ? 0 : 1);
  const rows = [...sec].sort((a, b) => rank(a) - rank(b)).map((g) => {
    const loc = g.locations.filter((l) => l.status !== 'exposed');
    const first = loc[0] || g.locations[0];
    const tierName = first?.tier;
    const rem = g.remediation;
    const action = rem ? `<a href="${esc(rem.pr.url)}" target="_blank" onclick="event.stopPropagation()">PR #${rem.pr.number} ↗</a>${g.issue ? ` · <a href="${esc(g.issue.url)}" target="_blank" onclick="event.stopPropagation()">Issue #${g.issue.number} ↗</a>` : ''}`
      : '<span class="muted">Review · no auto-fix</span>';
    return `<tr class="click" onclick="location.hash='#/finding/${esc(run.run_id)}/${esc(first.finding_id)}'">
      <td><div class="fw">${esc(g.cve || g.change_id)}</div><div class="muted small">${esc((g.title || '').slice(0, 60))}</div></td>
      <td><div>${esc(langOf(first.path))}</div><div class="muted small mono">${esc(g.package?.split(':').pop())} ${esc(g.installed)}</div></td>
      <td>${tierName === 'confirmed' ? '<span class="pill red">Confirmed</span>' : tierName === 'candidate' ? '<span class="pill amber">Candidate</span>' : tier(tierName)}</td>
      <td class="mono small">${loc.map((l) => `${esc(shortPath(l.path))}:${l.line}`).join('<br>')}</td>
      <td class="small">${action}</td></tr>`;
  }).join('');
  return `<section class="panel">
    <div class="p-head"><h3>Dependency vulnerabilities</h3><span class="muted small">Exact lines · version-checked against OSV · click a row for evidence</span></div>
    <table class="clean"><tr><th>Finding</th><th>Language / package</th><th>Confidence</th><th>Location</th><th>Action</th></tr>${rows}</table>
  </section>`;
}

function evidencePanel(o, run) {
  const g = o.evidence.guild, a = o.evidence.akash, c = o.evidence.clickhouse, s = o.evidence.semgrep;
  const guildRunning = ['RUNNING', 'STARTING'].includes(g.status);
  const okDot = (ok, running) => `<span class="dot ${running ? 'amber pulse' : ok ? 'green' : 'red'}"></span>`;
  const chips = [
    ['Guild', g.status === 'DONE', guildRunning, guildRunning ? 'agent running' : `${g.tool_calls.length} tool calls`],
    ['ClickHouse', !!c.vector_stats, false, c.vector_stats ? `${Math.round(c.vector_stats.elapsed_ms)} ms vector query` : ''],
    ['Akash', a.health?.deployment === 'akash', false, a.median_server_ms != null ? `${Math.round(a.median_server_ms)} ms inference` : ''],
    ['Semgrep', true, false, `${s.results} matches`],
    ['GitHub', true, false, '<span id="ciMini">CI…</span>'],
  ];
  return `<details class="panel evidence" id="evidence">
    <summary><h3>How DriftGuard investigated</h3>
      <div class="chips">${chips.map(([n, ok, run2, t]) => `<span class="ichip">${okDot(ok, run2)}${n}<span class="muted">${t}</span></span>`).join('')}</div>
      <span class="muted small">details ▾</span></summary>
    <div class="ev-grid">
      <div><div class="k">Guild.ai: watcher agent</div>
        ${g.session_url ? `<div><a href="${esc(g.session_url)}" target="_blank">Open session trace ↗</a></div>` : '<div class="muted">No watcher session in this run</div>'}
        ${guildRunning ? '<div class="muted small">Agent is fetching Stripe + OSV and reading lockfiles via Guild GitHub; evidence attaches when it finishes.</div>'
          : `<div class="small">Pinned <code>${esc(short(g.commit_sha))}</code> ${g.sha_agrees ? '<span class="pass">= platform</span>' : ''} · Stripe sha256 ${g.stripe_hash_agrees ? '<span class="pass">matches</span>' : 'n/a'} · ${esc(g.elapsed_s)}s</div>
             <ul class="calls">${g.tool_calls.map((t) => `<li>${esc(typeof t === 'string' ? t.replace(/ \((\d+|None) ms\)$/, '') : t.call)}</li>`).join('')}</ul>`}
        ${o.headline?.remediation?.pr?.executor === 'guild' ? `<div class="small">PR #${o.headline.remediation.pr.number} opened by the Guild remediator agent</div>` : ''}</div>
      <div><div class="k">Akash: inference service</div>
        <div class="small">deployment <b>${esc(a.health?.deployment)}</b> · pod <code>${esc((a.health?.host || '').slice(-11))}</code></div>
        <div class="small">${a.calls} calls · ${esc(a.median_server_ms)} ms server · ${esc(a.median_roundtrip_ms)} ms round trip (median)</div>
        <div class="small muted mono">${esc(a.health?.embedding_model || '')}</div><div class="small muted mono">${esc(a.health?.model_version || '')}</div></div>
      <div><div class="k">ClickHouse: vector search + analytics</div>
        <div class="small">cosineDistance query ${esc(c.vector_stats?.elapsed_ms)} ms · ${esc(c.vector_stats?.rows_read)} rows read · ${c.candidates} candidates</div>
        <div class="small"><a href="#/timeline/${esc(run.run_id)}">Timeline, SQL &amp; latency analytics →</a></div></div>
      <div><div class="k">Semgrep: exact lines</div>
        <div class="small">${esc(s.results)} matches in ${esc(s.elapsed_ms)} ms · v${esc(s.version)} · 5 tested rules</div>
        <div class="small muted">Type-aware rules ignore look-alike fields</div></div>
      <div><div class="k">GitHub: actions</div>
        <div class="small">Scanned <a href="https://github.com/${esc(run.repo)}/commit/${esc(run.commit_sha)}" target="_blank"><code>${esc(short(run.commit_sha))}</code></a> · draft PRs only, human merges</div>
        <div class="small" id="ciFull">CI status loading…</div></div>
    </div>
    ${(o.quarantine || []).length ? `<div class="q-note"><span class="dot amber"></span>Prompt-injection text in <code>${esc(o.quarantine[0].source)}</code> was quarantined: stored as evidence, never obeyed.</div>` : ''}
  </details>`;
}

async function benchmarkCard(runId) {
  const box = document.getElementById('bench');
  try {
    const b = await api(`/api/benchmark?run_id=${encodeURIComponent(runId)}`);
    const n = (m) => Math.round(m.value * m.n);
    box.innerHTML = `<summary><h3>Benchmark</h3>
        <div class="chips"><span class="ichip"><span class="dot green"></span>${b.case_recall.detected}/${b.case_recall.n}<span class="muted">detected, exact lines</span></span>
        <span class="ichip"><span class="dot green"></span>${b.false_positive_rate.incorrect}/${b.false_positive_rate.n}<span class="muted">false alerts on safe cases</span></span>
        <span class="ichip"><span class="dot green"></span>4<span class="muted">languages</span></span></div>
        <span class="muted small">small self-built corpus · details ▾</span></summary>
      <div class="ev-grid two">
        <table class="clean"><tr><th>Scenario</th><th>Lines</th><th>Tier</th><th></th></tr>${b.scenarios.map((s) => `<tr><td class="small"><b>${esc(s.scenario)}</b> ${esc(((b.scenario_titles || {})[s.scenario.split('/')[0]] || '').slice(0, 52))}</td>
          <td class="mono small">${esc(s.found_lines.join(', '))}</td><td>${s.tiers.map(tier).join(' ')}</td><td>${s.detected && s.exact_lines ? '<span class="pass">✓</span>' : '<span class="fail">✗</span>'}</td></tr>`).join('')}</table>
        <table class="clean"><tr><th>Negative / edge case</th><th>Observed</th><th></th></tr>${b.negatives.map((x) => `<tr><td class="small">${esc((b.edge_case_titles || {})[String(x.edge)] || EXTRA_NEG[x.edge] || x.edge)}</td>
          <td class="small mono">${esc(x.observed.join(', ') || 'no alert')}</td><td>${x.correct_non_alert ? '<span class="pass">✓</span>' : '<span class="fail">✗</span>'}</td></tr>`).join('')}</table>
      </div>
      <div class="muted small" style="padding:0 18px 14px">Version correctness: ${n(b.version_correctness)}/${b.version_correctness.n} pinned/dev/unverified cases not called broken.</div>`;
  } catch (e) { box.innerHTML = `<summary><h3>Benchmark</h3><span class="muted small">unavailable: ${esc(e.message)}</span></summary>`; }
}

// ------------------------------------------------------------------------------------------- Live investigation timeline
let INV_OPEN = null;      // which stage panel is expanded (survives re-render)
let INV_POLL = null;
let VEC_LIVE = null;      // result of a live vector re-run (real backend call)

const STAGES = [
  { id: 'github', icon: 'GH', name: 'GitHub', act: 'Snapshot repo, pin commit, inspect dependencies' },
  { id: 'guild', icon: 'G', name: 'Guild', act: 'Agent fetches Stripe changelog + OSV advisories' },
  { id: 'akash', icon: 'A', name: 'Akash', act: '384-d embeddings + relevance scores on the deployed model' },
  { id: 'clickhouse', icon: 'CH', name: 'ClickHouse', act: 'cosineDistance search over embedded code' },
  { id: 'semgrep', icon: 'SG', name: 'Semgrep', act: 'Exact files, lines and matched expressions' },
  { id: 'verify', icon: '✓', name: 'Verification', act: 'API-version gates, regression tests, safe exclusions' },
  { id: 'actions', icon: 'PR', name: 'GitHub actions', act: 'Issues, inline comments and verified draft PRs' },
];

function stageStates(L) {
  const has = (st, pred) => L.events.some((e) => e.stage === st && (!pred || pred(e)));
  const err = (sts) => L.events.some((e) => sts.includes(e.stage) && e.result === 'error');
  const done = L.status === 'complete';
  const g = L.guild.status;
  return {
    github: err(['repo_snapshot', 'inventory']) ? 'failed' : has('inventory') ? 'complete' : 'running',
    guild: g === 'DONE' ? 'complete' : g === 'ERROR' ? 'failed' : ['RUNNING', 'STARTING'].includes(g) ? 'running' : 'waiting',
    akash: has('ml_unavailable') ? 'failed' : has('ml_rank') || (done && has('ml_health')) ? 'complete' : has('ml_health') || has('source_fetch', (e) => e.provider === 'osv_unverified') ? 'running' : 'waiting',
    clickhouse: err(['vector_retrieval', 'code_index']) ? 'failed' : has('semgrep') && has('vector_retrieval') ? 'complete' : has('code_index') || has('vector_retrieval') ? 'running' : 'waiting',
    semgrep: err(['semgrep']) ? 'failed' : has('semgrep') ? 'complete' : has('vector_retrieval') ? 'running' : 'waiting',
    verify: done ? 'complete' : has('evidence_combine') || has('regression_proof') ? 'running' : 'waiting',
    actions: L.reports_error ? 'failed' : L.reports ? 'complete' : done ? 'running' : 'waiting',
  };
}

const evs = (L, st, pred) => L.events.filter((e) => e.stage === st && (!pred || pred(e)));
const ms = (v) => (v == null ? '—' : `${Math.round(v)} ms`);
const sim = (d) => (1 - d).toFixed(3);

function keyOutput(L, id) {
  const inv = evs(L, 'inventory')[0]?.details || {};
  const ov = L.overview;
  switch (id) {
    case 'github': return evs(L, 'repo_snapshot')[0] ? `<code>${esc(short(evs(L, 'repo_snapshot')[0].details.commit_sha))}</code> pinned · ${inv.packages ?? '…'} packages · ${(inv.languages || []).length || '…'} languages` : 'resolving branch → commit SHA…';
    case 'guild': {
      const g = L.guild;
      if (g.status === 'DONE') return `${g.tool_calls.length ? `${g.tool_calls.length} tool calls` : 'tool-call list in session trace'} · ${g.sources.map((s) => new URL(s.url).hostname).join(' + ')} · <a href="${esc(g.session_url)}" target="_blank" onclick="event.stopPropagation()">session ↗</a>`;
      if (g.session_url) return `agent running in Guild (non-blocking) · <a href="${esc(g.session_url)}" target="_blank" onclick="event.stopPropagation()">watch session ↗</a>`;
      return g.status === 'ERROR' ? esc(g.error || 'session failed') : 'starting Guild session…';
    }
    case 'akash': {
      const h = evs(L, 'ml_health')[0]?.details;
      const n = L.events.filter((e) => e.provider === 'akash').length;
      const med = ov?.evidence?.akash?.median_server_ms;
      return h ? `deployment <b>${esc(h.deployment)}</b> · ${L.ml_calls ? L.ml_calls.length : n} inference calls${med != null ? ` · ${ms(med)} median server` : ''}` : 'connecting…';
    }
    case 'clickhouse': {
      const v = evs(L, 'vector_retrieval');
      const first = v[0]?.details;
      return first ? `${v.length} vector queries · ${first.elapsed_ms} ms · ${first.rows_read} rows read · package = <code>${esc(first.package)}</code>` : 'waiting for embeddings…';
    }
    case 'semgrep': {
      const s = evs(L, 'semgrep')[0]?.details;
      return s ? `${s.results} matches in ${s.elapsed_ms} ms · e.g. <code>${esc((s.matches || []).find((m) => m.includes('subscription.ts')) || s.matches?.[0] || '')}</code>` : '…';
    }
    case 'verify': {
      const p = evs(L, 'regression_proof');
      const h = ov?.headline;
      if (h) return `<span class="fail">${h.proof.fail} FAIL</span> before → <span class="pass">${h.remediation?.after ? `${h.remediation.after.pass}/${h.remediation.after.pass + h.remediation.after.fail} PASS` : '—'}</span> after · acacia endpoint excluded`;
      return p.length ? `${p.filter((e) => e.result === 'reproduced').length}/${p.length} regressions reproduced…` : '…';
    }
    case 'actions': {
      if (!L.reports) return L.status === 'complete' ? 'updating GitHub (background)…' : 'after verification';
      const vals = Object.values(L.reports);
      const created = vals.filter((v) => v.issue?.action === 'created').length;
      return `${vals.length} issues (${created ? `${created} created now` : 'already filed earlier'}) · ${vals.reduce((a, v) => a + (v.pr_review?.posted || 0), 0)} new inline comments`;
    }
  }
  return '';
}

function vectorViz(L) {
  const S = L.stripe;
  if (!S) return '<div class="muted small">Available when the run completes.</div>';
  const sem = VEC_LIVE && VEC_LIVE.run === L.run.run_id ? { filtered_rows: VEC_LIVE.rows, stats: VEC_LIVE.stats } : S.semantic;
  const stripeFindings = L.findings.filter((f) => f.group_key === S.group_key).sort((a, b) => (b.model_score || 0) - (a.model_score || 0));
  const inBlock = (r) => stripeFindings.find((f) => f.path === r.path && f.line >= r.start_line && f.line <= r.end_line);
  const filteredKeys = new Set((S.semantic.filtered_rows || []).map((r) => `${r.path}:${r.start_line}`));
  const doc = evs(L, 'doc_index')[0]?.details || {};
  const h = L.overview?.evidence?.akash?.health || {};
  const excluded = (S.semantic.unfiltered_rows || []).filter((r) => !filteredKeys.has(`${r.path}:${r.start_line}`));
  return `<div class="vv">
    <div class="vv-l">
      <div class="k">1 · Official change → Akash</div>
      <div class="vv-card"><div class="fw">${esc(S.change.title)}</div>
        <div class="small muted">Removed: ${(S.change.removed_symbols || []).map((x) => `<code>${esc(x)}</code>`).join(' ')}</div>
        <div class="small" style="margin-top:6px">Embedded by <b>Akash</b> · <code>${esc(h.embedding_model || doc.embedding_model || '')}</code> · ${esc(h.embedding_dim || 384)}-d · pod <code>${esc((h.host || '').slice(-11))}</code></div></div>
      <div class="k" style="margin-top:12px">Akash ranker relevance (real scores)</div>
      ${stripeFindings.map((f) => `<div class="bar-row"><span class="mono small">${esc(shortPath(f.path))}:${f.line}</span>
        <div class="sbar"><div class="${f.tier === 'confirmed' ? 'g' : 'a'}" style="width:${Math.round((f.model_score || 0) * 100)}%"></div></div>
        <span class="mono small">${(f.model_score ?? 0).toFixed(3)}</span></div>`).join('')}
      <div class="small muted" style="margin-top:6px">Relevance rank from the trained ranker, not a probability.</div>
    </div>
    <div class="vv-r">
      <div class="k">2 · ClickHouse nearest code ${VEC_LIVE && VEC_LIVE.run === L.run.run_id ? '<span class="badge-live">RE-RUN LIVE</span>' : ''}</div>
      <div class="small muted">WHERE repo, commit, <b>package = 'stripe'</b> · ORDER BY cosineDistance · ${esc(sem.stats?.elapsed_ms)} ms · ${esc(sem.stats?.rows_read)} rows read
        ${VEC_LIVE && VEC_LIVE.run === L.run.run_id ? ` · Akash embed ${esc(VEC_LIVE.embed_ms)} ms` : ''}</div>
      <table class="clean vt"><tr><th>#</th><th>Code block</th><th>Distance</th><th>Similarity</th><th>Then</th></tr>
      ${(sem.filtered_rows || []).map((r, i) => { const f = inBlock(r); return `<tr class="${f ? (f.tier === 'confirmed' ? 'hl-g' : 'hl-a') : ''}"><td>${i + 1}</td>
        <td class="mono small">${esc(shortPath(r.path))}:${r.start_line} <span class="muted">${esc(r.symbol)}</span></td><td class="mono">${r.distance.toFixed(4)}</td><td class="mono">${sim(r.distance)}</td>
        <td class="small">${f ? (f.tier === 'confirmed' ? '<span class="pass">Semgrep ✓ confirmed</span>' : '<span class="tag amber">upgrade risk</span>') : '<span class="muted">not promoted</span>'}</td></tr>`; }).join('')}
      </table>
      ${excluded.length ? `<div class="k" style="margin-top:10px">Similar-looking, excluded by the package filter</div>
        ${excluded.slice(0, 3).map((r) => `<div class="small"><span class="tag amber">excluded</span> <span class="mono">${esc(shortPath(r.path))}:${r.start_line} ${esc(r.symbol)}</span> <span class="muted">distance ${r.distance.toFixed(4)} · no Stripe import</span></div>`).join('')}` : ''}
      <button class="btn ghost" id="vecLive" style="margin-top:10px">↻ Re-run vector query live</button>
    </div>
  </div>
  <div class="vv-foot"><span>Semantic similarity <b>finds candidates</b></span><span class="arr">→</span><span>API-version gate</span><span class="arr">+</span><span>Semgrep exact match</span><span class="arr">+</span><span>regression tests</span><span class="arr">=</span><span><b>finding</b></span></div>`;
}

function stagePanel(L, id) {
  const ov = L.overview;
  const done = L.status === 'complete';
  switch (id) {
    case 'github': {
      const r = evs(L, 'repo_snapshot')[0]?.details || {};
      const inv = evs(L, 'inventory')[0]?.details || {};
      return `<div class="kv2"><div>Repository</div><div><a href="${esc(r.url)}" target="_blank">${esc(r.repo)} ↗</a> · branch <code>${esc(r.branch)}</code></div>
        <div>Pinned commit</div><div><a href="${esc(r.url)}/commit/${esc(r.commit_sha)}" target="_blank"><code>${esc(r.commit_sha)}</code> ↗</a></div>
        <div>Dependencies</div><div>${esc(inv.packages)} packages · ${esc(inv.resolved)} resolved from lockfiles/exact pins · unverified: ${(inv.unverified || []).map((x) => `<code>${esc(x)}</code>`).join(' ') || 'none'}</div>
        <div>Languages</div><div>${(inv.languages || []).map(esc).join(', ')}</div>
        <div>Stripe API version</div><div>${Object.entries(inv.stripe_api_versions || {}).map(([a, v]) => `<code>${esc(a)}</code> → <code>${esc(v)}</code>`).join(' ')}</div></div>`;
    }
    case 'guild': {
      const g = L.guild;
      const own = evs(L, 'source_fetch', (e) => e.provider === 'stripe')[0]?.details;
      return `<div class="kv2"><div>Session</div><div>${g.session_url ? `<a href="${esc(g.session_url)}" target="_blank">${esc(g.session_url.split('/').pop())} ↗</a>` : '—'} · ${esc(g.status || 'not started')}${g.elapsed_s ? ` · ${esc(g.elapsed_s)} s end-to-end` : ''}${g.agent_runtime_s ? ` (agent ${esc(g.agent_runtime_s)} s)` : ''}</div>
        ${g.status !== 'DONE' ? `<div>Status</div><div class="muted">The agent is pinning the commit, reading lockfiles via Guild GitHub, and fetching Stripe + OSV. Its sources and tool calls appear here when the session finishes; the investigation does not wait for it.</div>
          <div>Independent cross-check</div><div>${own ? `Platform's own changelog fetch: sha256 <code>${esc((own.sha256 || '').slice(0, 12))}</code>` : '—'}</div></div>` : ''}
        ${g.status !== 'DONE' ? '' : `<div>Pinned by agent</div><div>${g.commit_sha ? `<code>${esc(short(g.commit_sha))}</code> ${g.commit_sha === L.run.commit_sha ? '<span class="pass">matches platform snapshot</span>' : ''}` : '—'} · ${esc(g.package_count ?? '—')} packages from ${(g.manifests || []).length} manifests</div>
        <div>Sources fetched by Guild</div><div>${g.sources.map((s) => `<div><code>${esc(s.status)}</code> ${esc(s.url)} · ${esc(s.bytes)} bytes · sha256 <code>${esc((s.sha256 || '').slice(0, 12))}</code></div>`).join('') || '—'}</div>
        <div>Independent cross-check</div><div>${own ? `Platform fetched the same changelog: sha256 <code>${esc((own.sha256 || '').slice(0, 12))}</code> ${L.stripe?.change?.guild_hash_agrees ? '<span class="pass">identical</span>' : ''}` : '—'}</div>
        <div>Tool calls</div><div>${g.tool_calls.length ? `<ol class="calls">${g.tool_calls.map((c) => `<li>${esc(c.call)}${c.ms != null ? ` <span class="muted">${c.ms} ms</span>` : ''}</li>`).join('')}</ol>` : `<span class="muted">Guild's events API was slow for this session; open the <a href="${esc(g.session_url)}" target="_blank">session trace ↗</a> for the call list.</span>`}</div></div>`}`;
    }
    case 'akash': {
      const h = evs(L, 'ml_health')[0]?.details || {};
      const by = (ep) => (L.ml_calls || []).filter((c) => c.endpoint === ep);
      const rows = ['/embed', '/rank', '/classify'].map((ep) => { const c = by(ep); return c.length ? `<div><code>POST ${ep}</code></div><div>${c.length} calls · ${c.reduce((a, x) => a + (x.n || 0), 0)} items · server ${c.map((x) => Math.round(x.server_ms || 0)).join(', ')} ms</div>` : ''; }).join('');
      return `<div class="kv2"><div>Endpoint</div><div><code>${esc(h.url || '')}</code> · deployment <b>${esc(h.deployment)}</b> · pod <code>${esc(h.host)}</code></div>
        <div>Model</div><div><code>${esc(h.embedding_model)}</code> (${esc(h.embedding_dim)}-d) + ranker <code>${esc(h.ranker_version)}</code> · version <code>${esc(h.model_version)}</code></div>
        <div>Health round trip</div><div>${ms(h.roundtrip_ms)}</div>
        ${rows || `<div>Calls</div><div>${evs(L, 'doc_index')[0] ? `${esc(evs(L, 'doc_index')[0].details.new_chunks)} change chunks embedded` : 'running…'}</div>`}</div>
        <div class="small muted" style="margin-top:6px">Relevance scores per code location are in the ClickHouse stage view.</div>`;
    }
    case 'clickhouse': return vectorViz(L);
    case 'semgrep': {
      const s = evs(L, 'semgrep')[0]?.details || {};
      const f = L.findings || [];
      return `<div class="small muted">${esc(s.results)} matches · ${esc(s.elapsed_ms)} ms · Semgrep ${esc(s.version)} · 5 tested rules</div>
        <table class="clean"><tr><th>Location</th><th>Rule</th><th>Matched expression</th><th>Tier</th></tr>
        ${(f.length ? f : []).filter((x) => x.rule_id).map((x) => `<tr class="click" onclick="location.hash='#/finding/${esc(L.run.run_id)}/${esc(x.finding_id)}'"><td class="mono small">${esc(x.path)}:${x.line}</td>
          <td class="mono small muted">${esc((x.rule_id || '').replace('driftguard.', ''))}</td><td class="mono small">${esc(x.matched)}</td><td>${tier(x.tier)}</td></tr>`).join('')
          || (s.matches || []).map((m) => `<tr><td class="mono small" colspan="4">${esc(m)}</td></tr>`).join('')}</table>`;
    }
    case 'verify': {
      const h = ov?.headline;
      const st = (L.findings || []).filter((x) => x.group_key === L.stripe?.group_key);
      const proofs = evs(L, 'regression_proof');
      return `<div class="vgrid">
        <div><div class="k">API-version gate (per code path)</div>${st.map((x) => `<div class="small"><span class="mono">${esc(shortPath(x.path))}:${x.line}</span> receives <code>${esc((x.gate.rule || '').split(' ')[0])}</code> → ${x.gate.affected ? '<span class="fail">affected</span>' : '<span class="tag amber">upgrade risk</span>'}</div>`).join('') || '…'}</div>
        <div><div class="k">Regression tests on unpatched code</div>${proofs.map((e) => `<div class="small"><code>${esc(e.details.playbook)}</code>: <span class="fail">${(e.details.failing || []).length} FAIL</span> / ${e.details.cases} cases · ${esc(e.result)}</div>`).join('') || '…'}
          ${h?.remediation?.after ? `<div class="small" style="margin-top:6px">Stripe fix: <span class="pass">${h.remediation.after.pass}/${h.remediation.after.pass + h.remediation.after.fail} PASS</span> <span class="muted">(${esc(h.remediation.source)})</span></div>` : ''}</div>
        <div><div class="k">Correctly excluded</div>
          ${st.filter((x) => x.tier === 'upgrade_risk').map((x) => `<div class="small"><span class="mono">${esc(shortPath(x.path))}:${x.line}</span>: pinned to <code>acacia</code>, not broken today</div>`).join('')}
          ${(L.safe_exclusions || []).map((u) => `<div class="small"><span class="mono">${esc(shortPath(u.path))}:${u.line}</span> ${esc(u.symbol)}: ${esc(u.why)}</div>`).join('')}
          ${(L.stripe?.semantic?.unfiltered_rows || []).filter((r) => r.path.endsWith('unused-field.ts')).map((r) => `<div class="small"><span class="mono">${esc(shortPath(r.path))}:${r.start_line}</span>: look-alike <code>current_period_end</code>, no Stripe type/import</div>`).join('')}</div>
      </div>`;
    }
    case 'actions': {
      const groups = ov ? [ov.headline, ...(ov.security || [])].filter(Boolean) : [];
      const rep = L.reports || {};
      const issueTxt = (a) => ({ created: 'created by this run', updated: 'updated by this run (filed earlier)', unchanged: 'filed by an earlier run · unchanged' }[a] || a);
      return groups.length ? `<table class="clean"><tr><th>Finding</th><th>Issue</th><th>Inline PR comments</th><th>Draft PR (verified patch)</th></tr>
        ${groups.map((g) => { const r = rep[g.group_key] || {}; const rem = g.remediation; return `<tr><td class="small"><b>${esc(g.cve || 'Stripe basil')}</b></td>
          <td class="small">${r.issue ? `<a href="${esc(r.issue.url)}" target="_blank">#${r.issue.number} ↗</a> <span class="muted">${esc(issueTxt(r.issue.action))}</span>` : (done ? '<span class="muted">confirmed findings only</span>' : '…')}</td>
          <td class="small">${r.pr_review ? `${r.pr_review.posted} posted now · ${r.pr_review.already_present} already present` : '—'}</td>
          <td class="small">${rem ? `<a href="${esc(rem.pr.url)}" target="_blank">#${rem.pr.number} ↗</a> <span class="muted">${rem.source === 'this run' ? 'opened by this run' : 'opened by ' + esc(rem.source)} · ${rem.pr.executor === 'guild' ? 'Guild remediator' : 'direct GitHub fallback'}</span>` : '<span class="muted">no auto-fix (candidate)</span>'}</td></tr>`; }).join('')}</table>
        <div class="small muted" style="margin-top:6px">PRs are only opened from a verified patch; this run did not open new PRs unless marked "opened by this run".</div>` : '<div class="muted small">After verification completes.</div>';
    }
  }
  return '';
}

function renderTimeline(L) {
  const box = document.getElementById('inv');
  if (!box) return;
  const S = stageStates(L);
  const nDone = Object.values(S).filter((x) => x === 'complete').length;
  const running = L.status === 'running';
  const secs = L.run.started_at ? Math.max(0, Math.round(((running ? Date.now() : new Date(L.run.finished_at)) - new Date(L.run.started_at)) / 1000)) : 0;
  box.innerHTML = `<div class="inv-head">
      <div><h3>Live investigation</h3><div class="small muted">${running ? `<span class="badge-live">RUNNING NOW</span>` : runBadge(L.run)} <code>${esc(L.run.run_id)}</code> · ${secs}s · ${L.events.length} measured events · click a stage for evidence</div></div>
      <div class="inv-prog"><div style="width:${Math.round((nDone / STAGES.length) * 100)}%"></div></div>
    </div>
    <div class="stages">${STAGES.map((st, i) => `<div class="stage ${S[st.id]} ${INV_OPEN === st.id ? 'open' : ''}" data-st="${st.id}">
      <div class="sh"><span class="si">${S[st.id] === 'complete' ? '✓' : S[st.id] === 'failed' ? '!' : st.icon}</span>
        <div class="sb"><div class="sn2">${i + 1}. ${st.name} <span class="sstate">${S[st.id] === 'running' ? '<span class="spin"></span> running' : S[st.id]}</span></div>
          <div class="sact">${st.act}</div><div class="sout">${keyOutput(L, st.id)}</div></div>
        <span class="chev">${INV_OPEN === st.id ? '▾' : '▸'}</span></div>
      ${INV_OPEN === st.id ? `<div class="spanel">${stagePanel(L, st.id)}</div>` : ''}</div>`).join('')}</div>`;
  box.querySelectorAll('.stage .sh').forEach((el) => {
    el.onclick = () => { const id = el.parentElement.dataset.st; INV_OPEN = INV_OPEN === id ? null : id; renderTimeline(L); };
  });
  const vb = document.getElementById('vecLive');
  if (vb) vb.onclick = async () => {
    vb.disabled = true; vb.innerHTML = '<span class="spin"></span> querying Akash + ClickHouse…';
    const r = await post('/api/sql/vector', { run_id: L.run.run_id, change_id: L.overview?.headline?.change_id });
    VEC_LIVE = { run: L.run.run_id, rows: r.rows, stats: r.stats, embed_ms: r.ml_calls?.[0]?.roundtrip_ms };
    renderTimeline(L);
  };
}

async function watchTimeline(runId, onComplete) {
  clearInterval(INV_POLL);
  let wasRunning = false;
  const tick = async () => {
    let L;
    try { L = await api(`/api/investigations/${encodeURIComponent(runId)}/live`); } catch (e) { return; }
    if (L.status === 'running') wasRunning = true;
    if (wasRunning && L.status !== 'running' && onComplete) { wasRunning = false; onComplete(L); }
    if (document.querySelector('#inv .spanel #vecLive:disabled')) return; // don't clobber an in-flight live query
    renderTimeline(L);
    const settled = L.status !== 'running' && !['RUNNING', 'STARTING'].includes(L.guild.status) && (L.reports || L.reports_error || L.status === 'error');
    if (settled) clearInterval(INV_POLL);
    return L;
  };
  const first = await tick();
  if (first && !(first.status !== 'running' && !['RUNNING', 'STARTING'].includes(first.guild.status) && (first.reports || first.reports_error))) {
    INV_POLL = setInterval(tick, 1500);
  }
  return first;
}


async function pageOverview(params) {
  setNav('overview');
  const o = await api(`/api/overview${params.get('run') ? '?run_id=' + encodeURIComponent(params.get('run')) : ''}`);
  FALLBACK = o.fallback_run_id;
  const run = o.run;
  const inv = await api(`/api/investigations/${encodeURIComponent(run.run_id)}`);
  $app.innerHTML = `
  <section class="hero2">
    <div class="h-left">
      <h1>Know exactly what breaks before it reaches production.</h1>
      <div class="h-meta">
        <a href="https://github.com/${esc(run.repo)}" target="_blank">${esc(run.repo)}</a>
        <span class="sep">·</span><code>${esc(short(run.commit_sha))}</code>
        <span class="sep">·</span>${runBadge(run)}
        <span class="sep">·</span><span class="muted">${Math.round((run.duration_ms || 0) / 1000)}s run</span>
        ${o.fallback_run_id && o.fallback_run_id !== run.run_id ? `<span class="sep">·</span><a class="link-muted" href="#/overview?run=${esc(o.fallback_run_id)}">recorded fallback</a>` : ''}
      </div>
    </div>
    <button class="btn big" id="liveRun">▶ Run live investigation</button>
  </section>
  <section id="inv" class="panel inv"></section>
  <div id="ovBody">
    <div id="staleNote"></div>
    ${heroMetrics(inv, o)}
    ${featured(run, o.headline)}
    ${findingsTable(run, o.security)}
    ${evidencePanel(o, run)}
    <details class="panel evidence" id="bench"><summary><h3>Benchmark</h3><span class="muted small"><span class="spin"></span> scoring…</span></summary></details>
  </div>`;
  document.getElementById('liveRun').onclick = startLiveFromOverview;
  watchTimeline(run.run_id);
  benchmarkCard(run.run_id);
  const pr = o.headline?.remediation?.pr;
  if (pr) {
    api(`/api/pr-status?url=${encodeURIComponent(pr.url)}`).then((st) => {
      const ok = st.checks.filter((c) => c.conclusion === 'success').length;
      const txt = `PR #${pr.number} CI ${ok}/${st.checks.length}`;
      document.getElementById('ciMini').textContent = txt;
      document.getElementById('ciFull').innerHTML = `<a href="${esc(pr.url)}/checks" target="_blank">${esc(txt)} checks passing ↗</a> · ${st.draft ? 'draft' : ''} · ${st.merged ? 'merged' : 'not merged'}`;
    }).catch(() => { document.getElementById('ciMini').textContent = 'CI n/a'; });
  }
}

async function startLiveFromOverview() {
  const btn = document.getElementById('liveRun');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Investigating live…';
  const { run_id } = await post('/api/investigations', {});
  RUN = run_id;
  VEC_LIVE = null;
  const body = document.getElementById('ovBody');
  body.classList.add('stale');
  document.getElementById('staleNote').innerHTML = '<div class="stale-note">Below: results of the previous run. They refresh when the live run completes.</div>';
  document.getElementById('inv').scrollIntoView({ behavior: 'smooth', block: 'start' });
  watchTimeline(run_id, (L) => {
    if (L.status === 'complete') location.hash = `#/overview?run=${run_id}`;
    else {
      btn.disabled = false; btn.textContent = '▶ Run live investigation';
      document.getElementById('staleNote').innerHTML = `<div class="notice bad">Live run failed: ${esc(L.error || '')}. ${FALLBACK ? `<a href="#/overview?run=${esc(FALLBACK)}">Open the recorded fallback run</a>` : ''}</div>`;
    }
  });
}

// ------------------------------------------------------------------------------------------- Page A
async function pageRepos() {
  setNav('repos');
  const [repo] = await api('/api/repos');
  const st = repo.stripe || {};
  const deps = (repo.direct || []).map((p) => `<tr><td><code>${esc(p.name)}</code></td><td>${esc(p.ecosystem)}</td>
    <td><code>${esc(p.version || p.constraint)}</code></td><td>${esc(p.scope)}</td><td class="small muted">${esc(p.version_source)} · ${esc(p.manifest)}</td></tr>`).join('');
  const stripeRows = Object.entries(st).map(([app, i]) => `
    <tr><td><code>${esc(app)}</code></td><td>client</td><td><code>${esc(i.effective_api_version)}</code></td>
      <td class="small muted">${esc(i.explicit_source ? 'apiVersion at ' + i.explicit_source : 'SDK default')} · stripe-node ${esc(i.sdk_version)} pins <code>${esc(i.sdk_default_api_version)}</code></td></tr>
    ${(i.webhook_endpoints || []).map((e) => `<tr><td><code>${esc(app)}</code></td><td>webhook <code>${esc(e.url)}</code></td>
      <td><code>${esc(e.api_version)}</code></td><td class="small muted">${esc(e.config)}</td></tr>`).join('')}`).join('');
  $app.innerHTML = `
  <section class="hero">
    <h1>Monitor dependencies across the open web. Fix what matters to your code.</h1>
    <p class="sub">DriftGuard watches official changelogs and advisories, pins your repository to an exact commit, finds the precise lines affected, proves breakage with recorded fixtures, and prepares a verified draft PR.</p>
  </section>
  <div class="grid g2">
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div><h2 style="margin:0"><a href="${esc(repo.html_url)}" target="_blank">${esc(repo.full_name)}</a></h2>
          <div class="small muted">${esc(repo.description)} · ${esc(repo.visibility)} · branch <code>${esc(repo.branch)}</code></div></div>
        <button class="btn" id="run">▶ Run full investigation</button>
      </div>
      <div class="grid g3" style="margin-top:14px">
        <div><div class="muted small">Last scanned SHA</div><div class="stat mono"><a target="_blank" href="${esc(repo.html_url)}/commit/${esc(repo.last_scan_sha)}">${esc(short(repo.last_scan_sha) || '—')}</a></div><div class="small muted">${fmtTime(repo.last_scan_at)}</div></div>
        <div><div class="muted small">Packages in lockfiles/manifests</div><div class="stat">${repo.package_count ?? '—'}</div><div class="small muted">${(repo.unverified || []).length} with unverified version</div></div>
        <div><div class="muted small">Languages</div><div style="margin-top:6px">${(repo.languages || []).map((l) => `<span class="chip">${esc(l)}</span>`).join('')}</div></div>
      </div>
      <div id="progress" style="margin-top:14px"></div>
    </div>
    <div class="card">
      <h2>Stripe API version gates</h2>
      <p class="small muted">Each code path is evaluated against the API version it actually receives.</p>
      <table><tr><th>App</th><th>Surface</th><th>API version</th><th>Basis</th></tr>${stripeRows || '<tr><td colspan=4 class="muted">No Stripe usage</td></tr>'}</table>
    </div>
  </div>
  <div class="card" style="margin-top:14px">
    <h2>Direct dependencies (resolved versions)</h2>
    <table><tr><th>Package</th><th>Ecosystem</th><th>Version</th><th>Scope</th><th>Source</th></tr>${deps}</table>
  </div>`;
  document.getElementById('run').onclick = startRun;
}

async function startRun() {
  const btn = document.getElementById('run');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Investigating…';
  const { run_id } = await post('/api/investigations', {});
  RUN = run_id;
  const box = document.getElementById('progress');
  clearInterval(POLL);
  POLL = setInterval(async () => {
    const ev = await api(`/api/investigations/${run_id}/events`);
    box.innerHTML = `<div class="timeline">${ev.events.map(evRow).join('')}</div>`;
    if (ev.status !== 'running') {
      clearInterval(POLL);
      if (ev.status === 'complete') location.hash = `#/changes`;
      else box.innerHTML += `<div class="notice bad">${esc(ev.error)}</div>`;
    }
  }, 1200);
}

// ------------------------------------------------------------------------------------------- Page B
const TABS = [['advisories', 'Security advisories'], ['breaking', 'Breaking API changes'], ['review', 'Needs review'], ['ignored', 'Ignored']];

async function pageChanges(params) {
  setNav('changes');
  const run = params.get('run') || await latestRun();
  if (!run) { $app.innerHTML = '<div class="card">No investigation yet. <a href="#/repos">Run one.</a></div>'; return; }
  const inv = await api(`/api/investigations/${run}`);
  const active = params.get('tab') || 'breaking';
  const TIER_RANK = ['confirmed', 'likely', 'candidate', 'upgrade_risk', 'review', 'version_unverified', 'inventory_only'];
  const rank = (t) => (TIER_RANK.includes(t) ? TIER_RANK.indexOf(t) : 99);
  const rows = inv.changes.filter((c) => c.tab === active).sort((a, b) => rank(a.top_tier) - rank(b.top_tier));
  const count = (t) => inv.changes.filter((c) => c.tab === t).length;
  const body = rows.map((c) => {
    const nFind = Object.values(c.counts || {}).reduce((a, b) => a + b, 0);
    const pr = inv.pr_by_group[c.group_key];
    const action = c.tab === 'ignored' ? `<span class="small muted">${esc(c.ignored_reason || 'no affected code')}</span>` :
      `<a href="#/group/${run}/${encodeURIComponent(c.group_key)}">${pr ? 'View PR ↗' : 'Investigate →'}</a>`;
    return `<tr class="${c.tab === 'ignored' ? '' : 'click'}" data-g="${esc(c.group_key)}">
      <td>${prov(c.provider)}</td>
      <td><div><b>${esc(c.title)}</b></div>
        <div class="small muted">${esc(c.cve || '')} ${c.cve ? '·' : ''} <code>${esc(c.change_id)}</code> ${c.severity ? '· ' + esc(c.severity) : ''}
        ${c.observation_state ? `· <span title="content hash vs previous fetch">${esc(c.observation_state)}</span>` : ''} ${c.source_mode && c.source_mode !== 'live' ? '· <b>' + esc(c.source_mode) + '</b>' : ''}</div></td>
      <td class="small">${c.installed ? `<code>${esc(c.package)} ${esc(c.installed)}</code>` : esc((c.affected_versions || []).join(', '))}</td>
      <td class="small muted">${esc((c.published_at || '').slice(0, 10))}</td>
      <td><a href="${esc(c.source_url)}" target="_blank" class="small">official source ↗</a></td>
      <td>${tier(c.top_tier)}</td>
      <td>${c.files} file${c.files === 1 ? '' : 's'}<div class="small muted">${nFind} finding${nFind === 1 ? '' : 's'}</div></td>
      <td>${action}</td></tr>`;
  }).join('');
  $app.innerHTML = `
  <h1>Upstream changes</h1>
  <p class="sub">${runBadge(inv)} Run <a href="#/timeline/${run}"><code>${esc(run)}</code></a> · ${esc(inv.repo)} @ <code>${esc(short(inv.commit_sha))}</code> · ${fmtTime(inv.finished_at)} · ${Math.round((inv.duration_ms || 0) / 1000)}s</p>
  ${inv.guild_watcher ? `<div class="notice good" style="margin-bottom:12px">Guild watcher session <a href="${esc(inv.guild_watcher.session_url)}" target="_blank">${esc(inv.guild_watcher.session_id)} ↗</a>
    · ${esc(inv.guild_watcher.status)} in ${esc(inv.guild_watcher.elapsed_s)}s · pinned <code>${esc(short((inv.guild_watcher.output || {}).commit_sha))}</code>
    ${(inv.guild_watcher.output || {}).commit_sha === inv.commit_sha ? '(agrees with platform snapshot)' : '<b>(SHA differs from platform snapshot)</b>'}
    · ${esc((inv.guild_watcher.output || {}).package_count)} packages via Guild GitHub integration</div>` : ''}
  <div class="tabs">${TABS.map(([k, l]) => `<a class="tab ${k === active ? 'active' : ''}" href="#/changes?run=${run}&tab=${k}">${l}<span class="n">${count(k)}</span></a>`).join('')}</div>
  <div class="card"><table>
    <tr><th></th><th>Change</th><th>Installed / versions</th><th>Published</th><th>Source</th><th>Confidence</th><th>Affected</th><th>Action</th></tr>
    ${body || '<tr><td colspan=8 class="muted">Nothing in this tab.</td></tr>'}</table></div>
  ${(inv.quarantine || []).length ? `<div class="notice" style="margin-top:14px"><b>Untrusted instruction-like text quarantined (${inv.quarantine.length}).</b>
    Stored as evidence only; never promoted to agent instructions.${inv.quarantine.map((q) => `<div class="small mono" style="margin-top:6px">${esc(q.source)}: “${esc(q.spans[0])}”</div>`).join('')}</div>` : ''}`;
  document.querySelectorAll('tr.click').forEach((tr) => { tr.onclick = () => { location.hash = `#/group/${run}/${encodeURIComponent(tr.dataset.g)}`; }; });
}

async function pageGroup(run, key) {
  const g = await api(`/api/investigations/${run}/groups/${encodeURIComponent(key)}`);
  const order = ['impacted', 'potentially_affected', 'upgrade_risk', 'needs_review', 'exposed', 'unverified'];
  const f = [...g.findings].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status))[0];
  location.replace(`#/finding/${run}/${f.finding_id}`);
}


// ------------------------------------------------------------------------------------------- vulnerable vs fixed code
function parseDiff(diff) {
  const files = {};
  let cur = null, hunk = null, o = 0, n = 0;
  for (const line of (diff || '').split('\n')) {
    const fm = line.match(/^diff --git a\/(.+?) b\/(.+)$/);
    if (fm) { cur = files[fm[2]] = []; hunk = null; continue; }
    const hm = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
    if (hm && cur) { o = +hm[1]; n = +hm[3]; hunk = { oldStart: o, oldCount: +(hm[2] ?? 1), lines: [] }; cur.push(hunk); continue; }
    if (!hunk || line.startsWith('+++') || line.startsWith('---') || line.startsWith('\\')) continue;
    if (line.startsWith('-')) hunk.lines.push({ t: 'del', o: o++, text: line.slice(1) });
    else if (line.startsWith('+')) hunk.lines.push({ t: 'add', n: n++, text: line.slice(1) });
    else hunk.lines.push({ t: 'ctx', o: o++, n: n++, text: line.slice(1) });
  }
  return files;
}

function hunkFor(files, f) {
  const hunks = files[f.path] || [];
  const needle = ((f.semgrep?.matched_code || '').split('\n')[0] || '').trim();
  return hunks.find((h) => needle && h.lines.some((l) => l.t === 'del' && l.text.trim() === needle))
    || hunks.find((h) => f.line >= h.oldStart && f.line < h.oldStart + h.oldCount);
}

function sideLines(h, side) {
  return `<div class="code">${h.lines.filter((l) => (side === 'old' ? l.t !== 'add' : l.t !== 'del')).map((l) => {
    const num = side === 'old' ? l.o : l.n;
    const cls = l.t === 'ctx' ? '' : l.t;
    return `<div class="ln ${cls}"><span class="n">${num}</span><span class="mk">${l.t === 'del' ? '−' : l.t === 'add' ? '+' : ' '}</span>${esc(l.text) || ' '}</div>`;
  }).join('')}</div>`;
}

function vulnVsFix(d, f, g, rem) {
  const blob = (sha, path, a, b) => `https://github.com/${d.repo}/blob/${sha}/${path}#L${a}${b && b !== a ? '-L' + b : ''}`;
  const sg = f.semgrep;
  const sev = g?.change?.severity ? `advisory ${g.change.severity}` : sg?.severity ? `semgrep ${sg.severity}` : '';
  const why = (sg?.message || f.reasons?.[0] || '').split('. ')[0];
  const left = `<div class="pane bad"><div class="ph"><b>Vulnerable code</b> · <a href="${blob(d.commit_sha, f.path, f.line, f.end_line)}" target="_blank" class="mono">${esc(f.path)}:${f.line}${f.end_line !== f.line ? '-' + f.end_line : ''} ↗</a>
      ${sev ? `<span class="sev">${esc(sev)}</span>` : ''} ${sg ? `<div class="mono small muted">${esc(sg.rule_id)}</div>` : ''}<div class="small">${esc(why)}.</div></div>
    ${codeView(f.code).replace('class="code"', 'class="code" style="border:0;border-radius:0"').replaceAll('ln hl', 'ln del')}</div>`;
  let right;
  if (rem && rem.diff) {
    const files = parseDiff(rem.diff);
    const h = hunkFor(files, f);
    const base = rem.base_sha || rem.commit_sha || d.commit_sha;
    const prLink = `<a href="${esc(rem.pr.url)}" target="_blank">PR #${rem.pr.number} ↗</a>`;
    if (h) {
      right = `<div class="pane good"><div class="ph"><b>Proposed fix</b> · accepted candidate <code>${esc(rem.accepted)}</code> · ${prLink}
          <div class="small">Tested: every existing and regression test passes on the patched code.</div></div>
        ${sideLines(h, 'new').replace('class="code"', 'class="code" style="border:0;border-radius:0"')}</div>`;
    } else {
      const manifest = Object.keys(files).filter((p) => /package\.json$|requirements[^/]*\.txt$|pom\.xml$/.test(p));
      right = `<div class="pane good"><div class="ph"><b>Proposed fix</b> · dependency upgrade (this line is unchanged; the call is safe on the fixed version) · ${prLink}</div>
        ${manifest.map((p) => `<div class="small mono" style="padding:6px 12px">${esc(p)}</div>${(files[p] || []).slice(0, 2).map((hh) => sideLines(hh, 'new').replace('class="code"', 'class="code" style="border:0;border-radius:0"')).join('')}`).join('')}</div>`;
    }
  } else {
    const fixed = g?.version_check?.fixed_versions || [];
    right = `<div class="pane good"><div class="ph"><b>Recommended fix</b> (no automatic PR for this tier)</div>
      <div style="padding:12px" class="small">${fixed.length ? `Upgrade <code>${esc(g.package?.name)}</code> past the affected range. OSV fix versions: ${fixed.map((v) => `<code>${esc(v)}</code>`).join(' ')}. Check the chosen version against OSV for other advisories.` : esc((f.limitations || [])[0] || 'Human review required.')}</div></div>`;
  }
  return `<div class="card" style="margin-top:14px"><h2>Vulnerable code → proposed fix</h2><div class="sbs">${left}${right}</div></div>`;
}

// ------------------------------------------------------------------------------------------- Page C
function highlight(text, terms) {
  let out = esc(text);
  for (const t of terms.filter(Boolean).sort((a, b) => b.length - a.length)) {
    const e = esc(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(new RegExp(`(${e})`, 'g'), '<mark>$1</mark>');
  }
  return out;
}

function codeView(code) {
  if (!code) return '';
  const [s, e] = code.highlight;
  return `<div class="code">${code.lines.map((l, i) => {
    const n = code.first_line + i;
    return `<div class="ln ${n >= s && n <= e ? 'hl' : ''}"><span class="n">${n}</span>${esc(l) || ' '}</div>`;
  }).join('')}</div>`;
}

function testTable(run, regressionNames) {
  if (!run) return '';
  return `<table><tr><th>Test</th><th>Result</th></tr>${run.cases.map((c) => `<tr>
    <td class="small">${esc(c.name)} ${regressionNames && regressionNames.includes(c.name) ? '<span class="chip">DriftGuard regression</span>' : ''}
      ${c.message ? `<div class="small muted mono">${esc(c.message.slice(0, 160))}</div>` : ''}</td>
    <td class="${c.status === 'pass' ? 'pass' : 'fail'}">${c.status.toUpperCase()}</td></tr>`).join('')}</table>`;
}

function diffView(diff) {
  return `<div class="diff">${esc(diff || '').split('\n').map((l) => {
    const cls = l.startsWith('+') && !l.startsWith('+++') ? 'a' : l.startsWith('-') && !l.startsWith('---') ? 'd' : l.startsWith('@@') ? 'h' : '';
    return `<span class="${cls}">${l}</span>`;
  }).join('\n')}</div>`;
}

async function pageFinding(run, fid) {
  setNav('changes');
  const d = await api(`/api/investigations/${run}/findings/${fid}`);
  const f = d.finding, g = d.group || {}, c = g.change || {};
  const sem = d.semantic;
  const ghBlob = `https://github.com/${d.repo}/blob/${d.commit_sha}/${f.path}#L${f.line}-L${f.end_line}`;
  const terms = [...(c.removed_symbols || []).map((s) => s.split('.').pop()), f.symbol];
  const srcText = g.source_text || c.summary || '';
  const gate = f.version_gate || {};
  const sg = f.semgrep;
  const proof = g.proof;
  const rem = g.remediation || (d.prior_remediation ? { ...d.prior_remediation, prior: true } : null);
  const sameBlock = sem && (sem.filtered_rows || []).find((r) => r.path === f.path && r.start_line <= f.line && f.line <= r.end_line);

  const why = [
    [f.finding_type === 'breaking_api' ? 'ok-i' : (gate.affected ? 'ok-i' : 'no-i'),
      f.finding_type === 'breaking_api' ? `Exact provider/package match: ${esc(g.hard_filter?.reason || 'stripe')}`
        : `Exact package match: <code>${esc(g.package?.name || f.symbol)} ${esc(g.package?.version || '')}</code> (${esc(g.package?.version_source || '')}, ${esc(g.package?.scope || '')})`],
    [gate.affected ? 'ok-i' : gate.affected === false ? 'x-i' : 'no-i',
      `Version gate: <code>${esc(gate.rule || 'n/a')}</code>${gate.basis ? `<div class="small muted">${esc(gate.basis)}</div>` : ''}`],
    [sg ? 'ok-i' : 'no-i', sg ? `Semgrep <code>${esc(sg.rule_id)}</code> matched <code>${esc(sg.matched_code.trim().slice(0, 100))}</code>` : 'No Semgrep code match (inventory evidence only)'],
    [sameBlock ? 'ok-i' : 'no-i', sameBlock ? `Semantic retrieval: rank #${sameBlock.rank} of ${sem.filtered_rows.length} filtered candidates, cosine distance <code>${sameBlock.distance.toFixed(4)}</code>` : 'Not in semantic candidate set'],
    [f.model_score != null ? 'ok-i' : 'no-i', f.model_score != null ? `Akash ranker score <code>${Number(f.model_score).toFixed(3)}</code> <span class="small muted">(${esc(f.model_version)}; relevance rank, not a probability)</span>` : 'Ranker not applied'],
    [f.test_status === 'reproduced' || f.test_status === 'patch_verified' ? 'ok-i' : 'no-i', {
      reproduced: 'Regression test reproduced the failure on the unpatched code', patch_verified: 'Patch verified: old and new fixtures pass',
      not_run: 'No behavioral test for this finding' }[f.test_status] || esc(f.test_status)],
  ];

  let left;
  if (g.kind === 'vulnerability') {
    const v = g.version_check || {};
    left = `<div class="row">${prov('osv')}<div><b>${esc(c.change_id)}</b> <span class="muted">${esc(c.cve || '')}</span></div></div>
      <div class="kv" style="margin:10px 0"><div>Severity</div><div>${esc(c.severity)}</div><div>Package</div><div><code>${esc(g.package?.ecosystem)}:${esc(g.package?.name)}</code></div>
      <div>Installed</div><div><code>${esc(v.installed)}</code> → ${v.affected ? '<span class="fail">affected</span>' : '<span class="pass">not affected</span>'}</div>
      <div>Range check</div><div class="small">${esc(v.reason)}</div><div>Fixed in</div><div>${(v.fixed_versions || []).map((x) => `<code>${esc(x)}</code>`).join(' ')}</div>
      <div>OSV IDs</div><div class="small">${(g.osv_ids || []).map(esc).join(', ')}</div><div>Published</div><div class="small">${esc(c.published_at)}</div>
      <div>Modified</div><div class="small">${esc(c.modified_at)}</div><div>Content hash</div><div class="small mono">${esc((c.content_sha256 || '').slice(0, 16))}… (${esc(c.observation_state)})</div></div>
      <a href="${esc(c.source_url)}" target="_blank">${esc(c.source_url)} ↗</a>
      <h3>Advisory text</h3><div class="src">${esc(srcText)}</div>`;
  } else {
    left = `<div class="row">${prov(c.provider || 'semgrep')}<div><b>${esc(c.title || f.change_id)}</b></div></div>
      <div class="kv" style="margin:10px 0"><div>API version</div><div><code>${esc(c.api_version || '')}</code></div>
      <div>Removed</div><div>${(c.removed_symbols || []).map((s) => `<code>${esc(s)}</code>`).join('<br>')}</div>
      <div>Replacement</div><div>${(c.added_symbols || []).map((s) => `<code>${esc(s)}</code>`).join('<br>')}</div>
      <div>Fetched</div><div class="small">${fmtTime(c.fetched_at)} · HTTP ${esc(c.http_status)} · <b>${esc(c.source_mode)}</b></div>
      <div>Content hash</div><div class="small mono">${esc((c.content_sha256 || '').slice(0, 16))}… (${esc(c.observation_state)})</div>
      ${c.guild_sha256 ? `<div>Guild fetch</div><div class="small">${c.guild_hash_agrees ? '<span class="pass">same sha256</span>' : '<span class="fail">different sha256</span>'} via Guild watcher</div>` : ''}</div>
      <a href="${esc(c.source_url || f.source_url)}" target="_blank">${esc(c.source_url || f.source_url)} ↗</a>
      <h3>Official source (highlighted)</h3><div class="src">${highlight(srcText, terms)}</div>
      ${(c.quarantined_instructions || []).length ? '<div class="notice">Instruction-like text in this source was quarantined.</div>' : ''}`;
  }

  const siblings = d.siblings.map((s) => `<tr class="click" onclick="location.hash='#/finding/${run}/${s.finding_id}'"><td class="mono small">${esc(s.path)}:${s.line}</td><td>${tier(s.confidence_tier)}</td></tr>`).join('');
  const nonMatching = (g.non_matching_uses || []).map((u) => `<li class="ok-i small"><code>${esc(u.path)}:${u.start_line}</code> ${esc(u.symbol)} — ${esc(u.verdict)}</li>`).join('');

  $app.innerHTML = `
  <div class="row" style="justify-content:space-between;flex-wrap:wrap">
    <div><a href="#/changes?run=${run}" class="small">← changes</a><h1 style="margin-top:4px">${esc(f.path)}:${f.line}</h1>
      <div class="sub">${tier(f.confidence_tier)} <span class="chip">${esc(f.status)}</span> <span class="chip">${esc(f.finding_type)}</span>
        ${d.issue ? `<a class="chip" style="color:var(--bad)" href="${esc(d.issue.url)}" target="_blank">GitHub issue #${d.issue.number} ↗</a>` : ''}
        ${d.pr_review && d.pr_review.posted + d.pr_review.already_present ? `<span class="chip">inline PR comments on #${d.pr_review.pr}</span>` : ''} scanned at <a target="_blank" href="https://github.com/${esc(d.repo)}/commit/${esc(d.commit_sha)}"><code>${esc(short(d.commit_sha))}</code></a></div></div>
    <div id="remBtnBox"></div>
  </div>
  <div class="detail">
    <div class="card">${left}</div>
    <div class="card">
      <div class="row" style="justify-content:space-between"><h2 style="margin:0">Code</h2><a href="${ghBlob}" target="_blank" class="small">${esc(f.path)} @ ${esc(short(d.commit_sha))} ↗</a></div>
      <div style="margin-top:10px">${codeView(f.code)}</div>
      ${sg ? `<h3>Semgrep</h3><div class="small"><code>${esc(sg.rule_id)}</code> · lines ${sg.start_line}–${sg.end_line} · cols ${sg.start_col}–${sg.end_col}</div>
        <div class="small muted" style="margin:6px 0">${esc(sg.message)}</div>
        <details><summary>Rule YAML (${esc(d.rule?.file)})</summary><pre class="sql">${esc(d.rule?.yaml)}</pre></details>` : ''}
      ${siblings ? `<h3>Other locations for this change</h3><table>${siblings}</table>` : ''}
      ${nonMatching ? `<h3>Uses that correctly did not match</h3><ul class="why">${nonMatching}</ul>` : ''}
    </div>
    <div class="card why">
      <h2>Why relevant?</h2>
      <ul>${why.map(([cls, txt]) => `<li class="${cls}">${txt}</li>`).join('')}</ul>
      <h3>Reasons</h3><ul>${f.reasons.map((r) => `<li class="small">• ${esc(r)}</li>`).join('')}</ul>
      ${f.limitations?.length ? `<h3>Limitations</h3>${f.limitations.map((l) => `<div class="notice small" style="margin-bottom:6px">${esc(l)}</div>`).join('')}` : ''}
    </div>
  </div>
  ${f.code ? vulnVsFix(d, f, g, rem) : ''}
  <div class="grid g2" style="margin-top:14px">
    <div class="card"><h2>Regression proof (unpatched code @ ${esc(short(d.commit_sha))})</h2>
      ${proof?.run ? `<div class="notice ${proof.status === 'reproduced' ? 'bad' : ''}" style="margin-bottom:10px">${proof.status === 'reproduced'
        ? 'Reproduced: pre-version fixtures PASS, post-version / security regression cases FAIL.' : esc(proof.status)}</div>${testTable(proof.run, proof.regression_case_names)}`
        : '<p class="muted small">No behavioral test applies to this finding. Static evidence only.</p>'}
    </div>
    <div class="card" id="remBox"><h2>Remediation</h2>${remediationView(rem, g)}</div>
  </div>
  ${sem ? `<div class="card" style="margin-top:14px"><h2>Semantic retrieval (ClickHouse cosineDistance over Akash embeddings)</h2>
    <div class="grid g2"><div><h3>Filtered: package = <code>${esc(c.package)}</code>, commit ${esc(short(d.commit_sha))} · ${esc(sem.stats?.elapsed_ms)} ms · ${esc(sem.stats?.rows_read)} rows read</h3>
      <table><tr><th>#</th><th>Block</th><th>Distance</th><th>Exact match?</th></tr>${(sem.filtered_rows || []).map((r) => {
        const hit = d.siblings.concat([f]).some((x) => x.path === r.path && r.start_line <= x.line && x.line <= r.end_line);
        return `<tr><td>${r.rank}</td><td class="mono small">${esc(r.path)}:${r.start_line} ${esc(r.symbol)}</td><td>${r.distance.toFixed(4)}</td><td>${hit ? '<span class="pass">Semgrep ✓</span>' : '<span class="muted">no — not promoted</span>'}</td></tr>`;
      }).join('')}</table></div>
      <div><h3>Baseline without hard filter · ${esc(sem.unfiltered_stats?.elapsed_ms)} ms</h3>
      <table><tr><th>#</th><th>Block</th><th>Distance</th><th>Hard filter</th></tr>${(sem.unfiltered_rows || []).map((r) => {
        const kept = (sem.filtered_rows || []).some((x) => x.path === r.path && x.start_line === r.start_line);
        return `<tr><td>${r.rank}</td><td class="mono small">${esc(r.path)}:${r.start_line} ${esc(r.symbol)}</td><td>${r.distance.toFixed(4)}</td>
          <td class="small">${kept ? 'kept' : '<span class="muted">excluded (no ' + esc(c.package) + ' import)</span>'}</td></tr>`;
      }).join('')}</table>
      <p class="small muted">Similarity alone ranks look-alike code too. It only nominates candidates; it never overrides a version gate or a test.</p></div></div>
    <details><summary>SQL</summary><pre class="sql">${esc(sem.sql)}</pre></details>
    <button class="btn ghost" id="liveVec" style="margin-top:8px">Re-run vector query live</button><div id="liveVecOut"></div></div>` : ''}`;

  if (g.remediable && !g.remediation && !d.prior_remediation) {
    document.getElementById('remBtnBox').innerHTML = '<button class="btn" id="remBtn">⚙ Prepare verified fix &amp; open draft PR</button>';
    document.getElementById('remBtn').onclick = () => startRemediation(run, f.group_key);
  }
  const lv = document.getElementById('liveVec');
  if (lv) lv.onclick = async () => {
    lv.disabled = true;
    const r = await post('/api/sql/vector', { run_id: run, change_id: f.change_id });
    const call = r.ml_calls[0] || {};
    document.getElementById('liveVecOut').innerHTML = `<p class="small">ClickHouse: <b>${r.stats.elapsed_ms} ms</b>, ${r.stats.rows_read} rows read, ${r.stats.result_rows} results ·
      Akash /embed: ${call.roundtrip_ms} ms roundtrip (${esc(call.model_version)})</p><pre class="sql">${esc(JSON.stringify(r.params, null, 1))}</pre>`;
    lv.disabled = false;
  };
}

function remediationView(rem, g) {
  if (!rem) {
    return g.remediable ? '<p class="muted small">A remediation playbook applies. Candidates run in isolated worktrees; a PR opens only if every test passes.</p>'
      : '<p class="muted small">No automatic fix for this tier (no reproduced failure / no playbook). Recommendation only; human follow-up.</p>' +
        (g.kind === 'vulnerability' && g.version_check?.fixed_versions?.length ? `<p class="small">Fixed versions per OSV: ${g.version_check.fixed_versions.map((v) => `<code>${esc(v)}</code>`).join(' ')}</p>` : '');
  }
  const pr = rem.pr;
  return `${rem.prior ? `<div class="small muted" style="margin-bottom:6px">PR opened for this same change in earlier run <code>${esc(rem.run_id)}</code> at <code>${esc(short(rem.commit_sha))}</code> (identical finding IDs).</div>` : ''}<div class="notice good">Draft PR <a href="${esc(pr.url)}" target="_blank"><b>#${pr.number}</b> ↗</a> on branch <code>${esc(pr.branch)}</code>
      · executor: <b>${esc(pr.executor === 'guild' ? 'Guild remediation agent' : 'direct GitHub API (disclosed fallback)')}</b>
      ${pr.guild_session_url ? ` · <a href="${esc(pr.guild_session_url)}" target="_blank">Guild trace ↗</a>` : ''}</div>
    <div id="ci" class="small" style="margin:8px 0"><span class="spin"></span> loading CI status…</div>
    <h3>Candidates</h3><table>${rem.attempts.map((a) => `<tr><td><code>${esc(a.candidate)}</code><div class="small muted">${esc(a.description)}</div></td>
      <td class="${a.verdict === 'accepted' ? 'pass' : 'fail'}">${esc(a.verdict.toUpperCase())}</td><td class="small">${esc(a.reason)}</td></tr>`).join('')}</table>
    ${rem.upgrade_plan ? `<p class="small">Upgrade <code>${esc(rem.upgrade_plan.current)}</code> → <code>${esc(rem.upgrade_plan.chosen)}</code>.
      ${rem.upgrade_plan.minimal_fix_remaining_advisories?.length ? `Minimal fix <code>${esc(rem.upgrade_plan.minimal_fix_for_target)}</code> would still carry ${rem.upgrade_plan.minimal_fix_remaining_advisories.length} advisories.` : ''}</p>` : ''}
    <details><summary>Accepted diff</summary>${diffView(rem.diff)}</details>`;
}

async function loadCI(url) {
  const box = document.getElementById('ci');
  if (!box) return;
  try {
    const s = await api(`/api/pr-status?url=${encodeURIComponent(url)}`);
    box.innerHTML = `PR ${esc(s.state)}${s.draft ? ' (draft)' : ''}${s.merged ? ' · merged' : ' · not merged (human approval required)'} · CI: ` +
      (s.checks.length ? s.checks.map((c) => `<a href="${esc(c.url)}" target="_blank" class="chip">${esc(c.name)}: ${esc(c.conclusion || c.status)}</a>`).join('') : 'no checks yet');
  } catch (e) { box.textContent = 'CI status unavailable'; }
}

async function startRemediation(run, key) {
  const btn = document.getElementById('remBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Testing candidate patches…';
  const { rem_id } = await post('/api/remediations', { run_id: run, group_key: key });
  const box = document.getElementById('remBox');
  clearInterval(POLL);
  POLL = setInterval(async () => {
    const r = await api(`/api/remediations/${rem_id}`);
    box.innerHTML = `<h2>Remediation</h2><div class="timeline">${(r.events || []).map(evRow).join('')}</div>`;
    if (r.status !== 'running') {
      clearInterval(POLL);
      if (r.status === 'pr_opened') route();
      else box.innerHTML += `<div class="notice bad">${esc(r.status)} ${esc(r.error || '')}</div>`;
    }
  }, 1500);
}

// ------------------------------------------------------------------------------------------- Page D
function evRow(e) {
  const d = typeof e.details === 'string' ? e.details : JSON.stringify(e.details);
  const w = Math.min(100, Math.log10(1 + (e.duration_ms || 0)) * 22);
  const cls = e.result === 'error' ? 'err' : e.result === 'rejected' ? 'rej' : '';
  return `<div class="ev"><div><b>${esc(e.stage)}</b><div class="small muted">${esc(e.provider)}</div></div>
    <div><div class="bar ${cls}" style="width:${w}%"></div><div class="small muted">${e.duration_ms} ms · ${esc(e.result)}</div></div>
    <div class="small mono" style="overflow-wrap:anywhere">${esc(d.slice(0, 420))}</div><div class="small muted">${esc(String(e.event_at).slice(11, 19))}</div></div>`;
}

function sqlCard(title, q) {
  return `<div class="card"><div class="row" style="justify-content:space-between"><h2 style="margin:0">${esc(title)}</h2>
    <span class="small muted">${q.stats.elapsed_ms} ms · ${q.stats.rows_read} rows read</span></div>
    <table style="margin-top:8px"><tr>${q.columns.map((c) => `<th>${esc(c)}</th>`).join('')}</tr>
    ${q.rows.slice(0, 14).map((r) => `<tr>${r.map((v) => `<td class="small ${typeof v === 'string' && v.length > 40 ? 'mono' : ''}">${esc(typeof v === 'string' && v.length > 70 ? v.slice(0, 70) + '…' : v)}</td>`).join('')}</tr>`).join('')}</table>
    <details><summary>SQL</summary><pre class="sql">${esc(q.sql)}</pre></details></div>`;
}

async function pageTimeline(run) {
  setNav('timeline');
  run = run || await latestRun();
  const [ev, an, runs] = await Promise.all([api(`/api/investigations/${run}/events`), api('/api/analytics'), api('/api/investigations')]);
  $app.innerHTML = `
  <h1>Investigation timeline</h1>
  <p class="sub">source fetched → parsed → ClickHouse candidate query → Akash inference → Semgrep → test → PR. Every row is a measured event stored in <code>run_events</code>.</p>
  <div class="row" style="margin-bottom:12px;flex-wrap:wrap">Run: <select id="runSel">${runs.map((r) => `<option value="${esc(r.run_id)}" ${r.run_id === run ? 'selected' : ''}>${esc(r.run_id)} · ${esc(short(r.commit_sha))} · ${esc(r.status)}</option>`).join('')}</select></div>
  <div class="card timeline">${ev.events.map(evRow).join('')}</div>
  <h1 style="margin-top:26px">ClickHouse analytics</h1>
  <p class="sub">Exact row counts and measured query latency from ClickHouse's own query summary.</p>
  <div class="grid g2">
    ${sqlCard('Corpus', an.corpus)}${sqlCard('Source observations by provider', an.provider_observations)}
    ${sqlCard('Findings by tier (latest state)', an.findings_by_tier)}${sqlCard('Exact vs inventory vs ranker', an.match_types)}
    ${sqlCard('Query latency (p50 / p95)', an.query_latency)}${sqlCard('Pipeline stage latency', an.stage_latency)}
    ${sqlCard('Snapshot dedupe (fetches vs distinct content)', an.dedupe)}${sqlCard('30-day observation history', an.observation_timeline)}
  </div>`;
  document.getElementById('runSel').onchange = (e) => { location.hash = `#/timeline/${e.target.value}`; };
}

// ------------------------------------------------------------------------------------------- router
async function route() {
  clearInterval(POLL);
  clearInterval(INV_POLL);
  const [path, query] = location.hash.slice(1).split('?');
  const parts = (path || '/overview').split('/').filter(Boolean);
  const params = new URLSearchParams(query || '');
  try {
    if (parts[0] === 'overview' || !parts[0]) await pageOverview(params);
    else if (parts[0] === 'changes') await pageChanges(params);
    else if (parts[0] === 'group') await pageGroup(parts[1], decodeURIComponent(parts.slice(2).join('/')));
    else if (parts[0] === 'finding') {
      await pageFinding(parts[1], parts[2]);
      const link = document.querySelector('#remBox a[href*="/pull/"]');
      if (link) loadCI(link.href);
    } else if (parts[0] === 'timeline') await pageTimeline(parts[1]);
    else await pageRepos();
  } catch (e) {
    $app.innerHTML = `<div class="notice bad">${esc(e.message)}</div>`;
  }
}
window.addEventListener('hashchange', route);
services();
route();
