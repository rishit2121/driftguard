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
    const pill = (label, ok, title, warn) => `<span class="svc ${ok ? (warn ? 'warn' : 'ok') : 'bad'}" title="${esc(title)}">${esc(label)}</span>`;
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
function evidenceCards(ev, run, headline) {
  const g = ev.guild, a = ev.akash, c = ev.clickhouse, s = ev.semgrep;
  const pr = headline?.remediation?.pr;
  return `<div class="grid g5">
    <div class="ev-card"><h4>Guild.ai ${g.status === 'DONE' ? '<span class="pass">✓</span>' : ['RUNNING', 'STARTING'].includes(g.status) ? '<span class="spin"></span>' : '<span class="fail">—</span>'}</h4>
      ${['RUNNING', 'STARTING'].includes(g.status) ? `<div>Watcher session ${g.session_url ? `<a href="${esc(g.session_url)}" target="_blank">running ↗</a>` : 'starting…'}</div>
        <div class="muted">Guild agent is fetching Stripe + OSV and reading lockfiles via Guild's GitHub integration; evidence attaches when it finishes.</div>`
      : g.session_url ? `<div>Watcher session <a href="${esc(g.session_url)}" target="_blank">trace ↗</a></div>
      <div class="muted">${g.tool_calls.length} tool calls · ${esc(g.elapsed_s)}s · pinned <code>${esc(short(g.commit_sha))}</code> ${g.sha_agrees ? '<span class="pass">= platform</span>' : ''}</div>
      <div class="muted">Stripe sha256 ${g.stripe_hash_agrees ? '<span class="pass">matches</span>' : 'n/a'}</div>` : '<div class="muted">no watcher session in this run</div>'}
      ${pr && pr.executor === 'guild' ? `<div style="margin-top:4px">PR <a href="${esc(pr.url)}" target="_blank">#${pr.number}</a> opened by Guild remediator</div>` : ''}</div>
    <div class="ev-card"><h4>Akash ${a.health?.deployment === 'akash' ? '<span class="pass">✓</span>' : `<span class="fail">${esc(a.health?.deployment || 'down')}</span>`}</h4>
      <div>deployment: <b>${esc(a.health?.deployment)}</b> · pod <code>${esc((a.health?.host || '').slice(-11))}</code></div>
      <div class="muted">${a.calls} inference calls · server ${esc(a.median_server_ms)} ms · round trip ${esc(a.median_roundtrip_ms)} ms (median)</div>
      <div class="muted small" style="overflow-wrap:anywhere">${esc(a.health?.model_version)}</div></div>
    <div class="ev-card"><h4>ClickHouse <span class="pass">✓</span></h4>
      <div>cosineDistance query <b>${esc(c.vector_stats?.elapsed_ms)} ms</b></div>
      <div class="muted">${esc(c.vector_stats?.rows_read)} rows read · ${c.candidates} filtered candidates</div>
      <div><a href="#/timeline/${esc(run.run_id)}">analytics &amp; timeline →</a></div></div>
    <div class="ev-card"><h4>Semgrep <span class="pass">✓</span></h4>
      <div>${esc(s.results)} matches · ${esc(s.elapsed_ms)} ms</div>
      <div class="muted">v${esc(s.version)} · 5 tested rules (ruleid/ok)</div>
      <div class="muted">typed rule ignores look-alike fields</div></div>
    <div class="ev-card"><h4>GitHub <span class="pass">✓</span></h4>
      <div>scanned <a href="https://github.com/${esc(run.repo)}/commit/${esc(run.commit_sha)}" target="_blank"><code>${esc(short(run.commit_sha))}</code></a></div>
      <div id="ciBox" class="muted">CI: loading…</div>
      <div class="muted">draft PRs only · human merges</div></div>
  </div>`;
}

function rejectSummary(reason) {
  const m = (reason || '').match(/^tests failed: (.*)$/s);
  if (!m) return reason;
  const failed = m[1].split('; ');
  return `${failed.length} tests failed, e.g. "${failed[0]}"`;
}

function headlineCard(run, h) {
  if (!h) return '';
  const rem = h.remediation;
  const confirmed = h.locations.filter((l) => l.tier === 'confirmed');
  const risk = h.locations.filter((l) => l.tier !== 'confirmed');
  return `<div class="card" style="margin-top:14px">
    <div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:8px">
      <div class="row">${prov('stripe')}<div><b style="font-size:16px">${esc(h.title)}</b>
        <div class="small muted">Stripe API <code>2025-03-31.basil</code> · <a href="${esc(h.source_url)}" target="_blank">official changelog ↗</a></div></div></div>
      <div>${h.issue ? `<a class="chip" style="color:var(--bad)" href="${esc(h.issue.url)}" target="_blank">issue #${h.issue.number} ↗</a>` : ''} ${tier('confirmed')}</div>
    </div>
    <div class="flow" style="margin-top:12px">
      <div class="step"><div class="lbl">1 · Exact code affected (Semgrep)</div>
        ${confirmed.map((l) => `<div><a class="mono small" href="#/finding/${esc(run.run_id)}/${esc(l.finding_id)}">${esc(l.path.replace('apps/billing-ts/src/', ''))}:${l.line}</a></div>`).join('')}
        ${risk.map((l) => `<div class="small"><a class="mono" href="#/finding/${esc(run.run_id)}/${esc(l.finding_id)}">${esc(l.path.replace('apps/billing-ts/src/', ''))}:${l.line}</a> <span class="tier upgrade_risk">upgrade risk</span></div>`).join('')}
        <div class="small muted" style="margin-top:4px">legacy endpoint pinned to <code>acacia</code>: not called broken</div></div>
      <div class="arrow">→</div>
      <div class="step"><div class="lbl">2 · Proof on unpatched code</div>
        <div class="score"><span class="fail">${h.proof.fail} FAIL</span> <span class="muted" style="font-size:14px">post-basil fixtures</span></div>
        <div class="score" style="font-size:16px"><span class="pass">${h.proof.pass} PASS</span> <span class="muted" style="font-size:13px">pre-basil + existing tests</span></div>
        <div class="small muted">recorded pre/post fixtures replayed through production code</div></div>
      <div class="arrow">→</div>
      <div class="step"><div class="lbl">3 · Verified fix → draft PR</div>
        ${rem ? `${rem.attempts.map((a) => `<div class="${a.verdict === 'accepted' ? 'accept' : 'reject'}"><b>${esc(a.verdict.toUpperCase())}</b> <code>${esc(a.candidate)}</code>
            <div class="muted small">${esc(a.verdict === 'accepted' ? a.reason : rejectSummary(a.reason))}</div></div>`).join('')}
          ${rem.after ? `<div class="small" style="margin-top:4px">After patch: <span class="pass">${rem.after.pass}/${rem.after.pass + rem.after.fail} PASS</span></div>` : ''}
          <div style="margin-top:6px"><a href="${esc(rem.pr.url)}" target="_blank"><b>Draft PR #${rem.pr.number} ↗</b></a> <span class="small muted">by ${esc(rem.pr.executor === 'guild' ? 'Guild remediator agent' : 'direct GitHub fallback')}</span></div>
          <div class="small muted">from ${esc(rem.source)}</div>`
        : '<div class="muted small">No remediation yet for this change.</div>'}</div>
    </div></div>`;
}

function securityCards(run, sec) {
  return `<div class="grid g3" style="margin-top:14px">${sec.map((g) => {
    const rem = g.remediation;
    const rejected = rem ? rem.attempts.filter((a) => a.verdict === 'rejected') : [];
    const loc = g.locations.filter((l) => l.status !== 'exposed');
    return `<div class="card"><div class="row" style="justify-content:space-between"><div class="row">${prov('osv')}<div><b>${esc(g.cve || g.change_id)}</b>
        <div class="small muted"><code>${esc(g.package)} ${esc(g.installed)}</code> · ${esc(langOf(loc[0]?.path))}</div></div></div>${tier(loc[0]?.tier)}</div>
      <div style="margin-top:8px">${loc.map((l) => `<a class="mono small" href="#/finding/${esc(run.run_id)}/${esc(l.finding_id)}">${esc(l.path.split('/').slice(-2).join('/'))}:${l.line}</a>`).join(' · ')}</div>
      ${g.proof.status === 'reproduced' ? `<div class="small" style="margin-top:6px">Proof: <span class="fail">${g.proof.fail} FAIL</span> on unpatched code (inert probe)</div>` : `<div class="small muted" style="margin-top:6px">Candidate use site only: exploitability not claimed</div>`}
      ${rejected.map((a) => `<div class="reject"><b>REJECTED</b> <code>${esc(a.candidate)}</code> <span class="muted small">${esc(a.reason.slice(0, 90))}</span></div>`).join('')}
      ${rem ? `<div class="accept"><b>ACCEPTED</b> <code>${esc(rem.accepted)}</code>${rem.upgrade_plan?.minimal_fix_remaining ? `<div class="muted small">minimal fix ${esc(rem.upgrade_plan.minimal_fix)} still has ${rem.upgrade_plan.minimal_fix_remaining} advisories, so not chosen</div>` : ''}</div>
        <div class="small"><a href="${esc(rem.pr.url)}" target="_blank">Draft PR #${rem.pr.number} ↗</a> <span class="muted">(${esc(rem.source)})</span>
          ${g.issue ? ` · <a href="${esc(g.issue.url)}" target="_blank">issue #${g.issue.number} ↗</a>` : ''}</div>` : ''}
    </div>`;
  }).join('')}</div>`;
}

const EXTRA_NEG = {
  'E-constant': 'Constant Log4j message (RequestAudit.java:26) must not be flagged',
  shopify: '40 live Shopify changelog entries, repo has no Shopify usage: no alerts',
  'stripe-sdk-osv': 'stripe-node 18.0.0 has no OSV advisories: no CVE alert',
};

async function benchmarkCard(runId) {
  const box = document.getElementById('bench');
  try {
    const b = await api(`/api/benchmark?run_id=${encodeURIComponent(runId)}`);
    const pct = (m) => `${m.detected ?? Math.round(m.value * m.n)}/${m.n}`;
    box.innerHTML = `<div class="row" style="justify-content:space-between;flex-wrap:wrap"><h2 style="margin:0">Benchmark, scored live against this run</h2>
      <span class="small muted">demo repo <code>benchmark/run_benchmark.py</code> · small hand-built corpus</span></div>
      <div class="grid g4" style="margin:10px 0">
        <div><div class="muted small">Impacted scenarios detected</div><div class="score pass">${pct(b.case_recall)}</div></div>
        <div><div class="muted small">Exact line localization</div><div class="score pass">${Math.round(b.exact_line_localization.value * b.exact_line_localization.n)}/${b.exact_line_localization.n}</div></div>
        <div><div class="muted small">False alerts on known-safe cases</div><div class="score pass">${b.false_positive_rate.incorrect}/${b.false_positive_rate.n}</div></div>
        <div><div class="muted small">Pinned / dev / unverified not called broken</div><div class="score pass">${Math.round(b.version_correctness.value * b.version_correctness.n)}/${b.version_correctness.n}</div></div>
      </div>
      <div class="grid g2">
        <table><tr><th>Scenario</th><th>Lines found</th><th>Tier</th><th></th></tr>${b.scenarios.map((s) => `<tr><td class="small"><b>${esc(s.scenario)}</b> ${esc((b.scenario_titles || {})[s.scenario.split('/')[0]] || '').slice(0, 64)}</td>
          <td class="mono small">${esc(s.found_lines.join(', '))}</td><td>${s.tiers.map(tier).join(' ')}</td><td>${s.detected && s.exact_lines ? '<span class="pass">✓</span>' : '<span class="fail">✗</span>'}</td></tr>`).join('')}</table>
        <table><tr><th>Negative / edge case</th><th>Observed</th><th></th></tr>${b.negatives.map((n) => `<tr><td class="small">${esc((b.edge_case_titles || {})[String(n.edge)] || EXTRA_NEG[n.edge] || n.edge)}</td>
          <td class="small mono">${esc(n.observed.join(', ') || 'no alert')}</td><td>${n.correct_non_alert ? '<span class="pass">✓</span>' : '<span class="fail">✗</span>'}</td></tr>`).join('')}</table>
      </div>`;
  } catch (e) { box.innerHTML = `<div class="muted">Benchmark unavailable: ${esc(e.message)}</div>`; }
}

async function pageOverview(params) {
  setNav('overview');
  const o = await api(`/api/overview${params.get('run') ? '?run_id=' + encodeURIComponent(params.get('run')) : ''}`);
  FALLBACK = o.fallback_run_id;
  const run = o.run;
  $app.innerHTML = `
  <div class="row" style="justify-content:space-between;flex-wrap:wrap;gap:10px">
    <div><h1 style="margin:0">When the outside world changes, see exactly what breaks.</h1>
      <div class="sub" style="margin:6px 0 0">${runBadge(run)} &nbsp;<a href="https://github.com/${esc(run.repo)}" target="_blank">${esc(run.repo)}</a> @ <code>${esc(short(run.commit_sha))}</code>
        · ${Math.round((run.duration_ms || 0) / 1000)}s · run <a href="#/timeline/${esc(run.run_id)}"><code>${esc(run.run_id)}</code></a>
        ${o.fallback_run_id && o.fallback_run_id !== run.run_id ? ` · <a href="#/overview?run=${esc(o.fallback_run_id)}">open recorded fallback run</a>` : ''}</div></div>
    <button class="btn" id="liveRun">▶ Run live investigation</button>
  </div>
  <div id="liveBox"></div>
  <div style="margin-top:14px">${evidenceCards(o.evidence, run, o.headline)}</div>
  ${headlineCard(run, o.headline)}
  ${securityCards(run, o.security)}
  <div class="card" id="bench" style="margin-top:14px"><span class="spin"></span> scoring benchmark…</div>
  ${(o.quarantine || []).length ? `<div class="notice" style="margin-top:14px"><b>Prompt-injection text quarantined</b> in ${esc(o.quarantine[0].source)}: “${esc(o.quarantine[0].spans[0].slice(0, 110))}…” Stored as evidence only; no agent or tool acted on it.</div>` : ''}`;
  document.getElementById('liveRun').onclick = startLiveFromOverview;
  benchmarkCard(run.run_id);
  if (['RUNNING', 'STARTING'].includes(o.evidence.guild.status)) {
    POLL = setInterval(async () => {
      const fresh = await api(`/api/overview?run_id=${encodeURIComponent(run.run_id)}`);
      if (!['RUNNING', 'STARTING'].includes(fresh.evidence.guild.status)) { clearInterval(POLL); route(); }
    }, 4000);
  }
  const pr = o.headline?.remediation?.pr;
  if (pr) {
    api(`/api/pr-status?url=${encodeURIComponent(pr.url)}`).then((st) => {
      const ok = st.checks.filter((c) => c.conclusion === 'success').length;
      document.getElementById('ciBox').innerHTML = `PR #${pr.number} CI: <span class="${ok === st.checks.length ? 'pass' : 'fail'}">${ok}/${st.checks.length} checks pass</span> · ${st.draft ? 'draft' : ''} ${st.merged ? 'merged' : 'unmerged'}`;
    }).catch(() => { document.getElementById('ciBox').textContent = 'CI status unavailable'; });
  }
}

async function startLiveFromOverview() {
  const btn = document.getElementById('liveRun');
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span> Live investigation running…';
  const { run_id } = await post('/api/investigations', {});
  RUN = run_id;
  const box = document.getElementById('liveBox');
  const t0 = Date.now();
  clearInterval(POLL);
  POLL = setInterval(async () => {
    const ev = await api(`/api/investigations/${run_id}/events`);
    const secs = Math.round((Date.now() - t0) / 1000);
    box.innerHTML = `<div class="card" style="margin-top:12px"><div class="row" style="justify-content:space-between"><b>Live run <code>${esc(run_id)}</code></b><span class="muted small">${secs}s elapsed · ${ev.events.length} measured events</span></div>
      <div class="timeline">${ev.events.slice(-8).map(evRow).join('')}</div></div>`;
    if (ev.status !== 'running') {
      clearInterval(POLL);
      if (ev.status === 'complete') location.hash = `#/overview?run=${run_id}`;
      else box.innerHTML += `<div class="notice bad">Live run failed: ${esc(ev.error)}. ${FALLBACK ? `<a href="#/overview?run=${esc(FALLBACK)}">Open the recorded fallback run</a>` : ''}</div>`;
    }
  }, 1500);
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
