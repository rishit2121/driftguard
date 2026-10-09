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
  <p class="sub">Run <a href="#/timeline/${run}"><code>${esc(run)}</code></a> · ${esc(inv.repo)} @ <code>${esc(short(inv.commit_sha))}</code> · ${fmtTime(inv.finished_at)} · ${Math.round((inv.duration_ms || 0) / 1000)}s</p>
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
  const rem = g.remediation;
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
      <div>Content hash</div><div class="small mono">${esc((c.content_sha256 || '').slice(0, 16))}… (${esc(c.observation_state)})</div></div>
      <a href="${esc(c.source_url || f.source_url)}" target="_blank">${esc(c.source_url || f.source_url)} ↗</a>
      <h3>Official source (highlighted)</h3><div class="src">${highlight(srcText, terms)}</div>
      ${(c.quarantined_instructions || []).length ? '<div class="notice">Instruction-like text in this source was quarantined.</div>' : ''}`;
  }

  const siblings = d.siblings.map((s) => `<tr class="click" onclick="location.hash='#/finding/${run}/${s.finding_id}'"><td class="mono small">${esc(s.path)}:${s.line}</td><td>${tier(s.confidence_tier)}</td></tr>`).join('');
  const nonMatching = (g.non_matching_uses || []).map((u) => `<li class="ok-i small"><code>${esc(u.path)}:${u.start_line}</code> ${esc(u.symbol)} — ${esc(u.verdict)}</li>`).join('');

  $app.innerHTML = `
  <div class="row" style="justify-content:space-between;flex-wrap:wrap">
    <div><a href="#/changes?run=${run}" class="small">← changes</a><h1 style="margin-top:4px">${esc(f.path)}:${f.line}</h1>
      <div class="sub">${tier(f.confidence_tier)} <span class="chip">${esc(f.status)}</span> <span class="chip">${esc(f.finding_type)}</span> scanned at <a target="_blank" href="https://github.com/${esc(d.repo)}/commit/${esc(d.commit_sha)}"><code>${esc(short(d.commit_sha))}</code></a></div></div>
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

  if (g.remediable && !rem) {
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
  return `<div class="notice good">Draft PR <a href="${esc(pr.url)}" target="_blank"><b>#${pr.number}</b> ↗</a> on branch <code>${esc(pr.branch)}</code>
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
  const parts = (path || '/repos').split('/').filter(Boolean);
  const params = new URLSearchParams(query || '');
  try {
    if (parts[0] === 'changes') await pageChanges(params);
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
