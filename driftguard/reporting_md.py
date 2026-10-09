"""Developer-facing Markdown for DriftGuard PRs and Issues (shared by creation and in-place refresh).

Everything rendered here comes from stored run evidence or live GitHub data; nothing is synthesized.
"""
from datetime import datetime, timezone

TEST_CMD = {
    "apps/billing-ts": "cd apps/billing-ts && npm ci && npm test",
    "apps/account-js": "cd apps/account-js && npm ci && npm test",
    "apps/ingestion-py": "cd apps/ingestion-py && pip install -r requirements.txt pytest==8.3.3 && python -m pytest -q",
    "apps/audit-java": "cd apps/audit-java && mvn -B test",
}


def _link(repo, sha, path, line):
    return f"https://github.com/{repo}/blob/{sha}/{path}#L{line}"


def _app(path):
    return "/".join(path.split("/")[:2])


def _cases(run):
    cases = (run or {}).get("cases", [])
    return [c for c in cases if c["status"] == "pass"], [c for c in cases if c["status"] == "fail"]


def context(state, group, findings, rem, proof, issue=None, ci=None, latest=None):
    """Normalize everything the templates need. `rem` is a stored remediation (attempts/accepted/pr/upgrade_plan)."""
    change = group["change"]
    impacted = [f for f in findings if f["confidence_tier"] == "confirmed" or (f["status"] == "impacted")]
    others = [f for f in findings if f not in impacted and f["status"] != "exposed"]
    accepted = next((a for a in (rem or {}).get("attempts", []) if a.get("verdict") == "accepted"), None)
    return {
        "repo": state["repo"], "kind": group["kind"], "change": change, "group": group, "impacted": impacted, "others": others,
        "scan_sha": (rem or {}).get("commit_sha") or state["commit_sha"], "scan_run": (rem or {}).get("run_id") or state["run_id"],
        "latest": latest, "rem": rem, "accepted": accepted,
        "rejected": [a for a in (rem or {}).get("attempts", []) if a.get("verdict") == "rejected"],
        "proof": proof, "issue": issue, "ci": ci, "pr": (rem or {}).get("pr"),
    }


LANG = {"ts": "typescript", "js": "javascript", "py": "python", "java": "java", "json": "json", "txt": "text", "xml": "xml"}


def _diff_files(diff):
    files, cur, hunk = {}, None, None
    for line in (diff or "").splitlines():
        if line.startswith("diff --git"):
            cur = files.setdefault(line.split(" b/")[-1], [])
            hunk = None
            continue
        if cur is None or line.startswith(("+++", "---", "index ", "new file", "deleted file")):
            continue
        if line.startswith("@@"):
            hunk = [line]
            cur.append(hunk)
        elif hunk is not None:
            hunk.append(line)
    return files


def _fix_hunk(diff, f):
    needle = ((f.get("semgrep") or {}).get("matched_code") or "").splitlines()
    needle = needle[0].strip() if needle else ""
    for h in _diff_files(diff).get(f["path"], []):
        if needle and any(l.startswith("-") and l[1:].strip() == needle for l in h):
            return "\n".join(h)
    return None


def _snippet(f, pad=3):
    code = f.get("code") or {}
    lines, first = code.get("lines") or [], code.get("first_line", 1)
    if not lines:
        return None, None, None
    a = max(f["line"] - pad, first)
    b = min(f.get("end_line", f["line"]) + pad, first + len(lines) - 1)
    return a, b, "\n".join(lines[a - first : b - first + 1])


def _why(c, f):
    sg = f.get("semgrep") or {}
    gate = f.get("version_gate") or {}
    msg = (sg.get("message") or "").strip().split(". ")[0].rstrip(".")
    if gate.get("api_version"):
        ctx = f"This code path receives Stripe API `{gate['api_version']}` ({gate.get('basis', '')})."
    elif gate.get("installed"):
        ctx = f"Installed `{gate['installed']}` is in the affected range: {gate.get('rule', '')}."
    else:
        ctx = ""
    return f"{msg}. {ctx}".strip()


def exact_code_section(c):
    """Per-location evidence: permalink, real snippet from the scanned commit, rule, why, and the tested correction."""
    repo, sha = c["repo"], c["scan_sha"]
    diff = (c["rem"] or {}).get("diff")
    out = ["## 🔍 Exact Affected Code & Locations", "",
           f"Scanned commit [`{sha[:7]}`](https://github.com/{repo}/commit/{sha}). Lines and snippets come from that commit and the Semgrep findings.", ""]
    manifest_shown = False
    for i, f in enumerate(c["impacted"], 1):
        sg = f.get("semgrep") or {}
        a, b, snip = _snippet(f)
        ext = f["path"].rsplit(".", 1)[-1]
        link = f"https://github.com/{repo}/blob/{sha}/{f['path']}#L{f['line']}" + (f"-L{f['end_line']}" if f.get("end_line", f["line"]) != f["line"] else "")
        out += [f"### {i}. [`{f['path']}:{f['line']}`]({link})", "",
                f"**Rule:** `{sg.get('rule_id', 'n/a')}` · **Affected expression (line {f['line']}):** `{(sg.get('matched_code') or '').strip()[:140]}`", "",
                f"**Why:** {_why(c, f)}", ""]
        if snip:
            out += [f"Lines {a}–{b} at `{sha[:7]}`:", f"```{LANG.get(ext, '')}", snip, "```", ""]
        hunk = _fix_hunk(diff, f) if diff else None
        if hunk:
            out += ["**Proposed correction** (tested patch):", "```diff", hunk, "```", ""]
        elif diff and not manifest_shown:
            manifests = {p: h for p, h in _diff_files(diff).items() if p.endswith(("package.json", "requirements.txt", "pom.xml"))}
            if manifests:
                manifest_shown = True
                out += ["**Proposed correction** (tested patch): this call site stays as is, and the dependency is upgraded out of the affected range:"]
                for p, hs in manifests.items():
                    out += [f"`{p}`", "```diff", "\n".join(hs[0]), "```"]
                out.append("")
        elif not diff:
            fixed = c["group"].get("version_check", {}).get("fixed_versions") or []
            if fixed:
                out += [f"**Recommended correction:** upgrade past the affected range (OSV fix versions: {', '.join(f'`{v}`' for v in fixed)}).", ""]
    for f in c["others"]:
        if f["confidence_tier"] == "upgrade_risk":
            a, b, snip = _snippet(f, pad=1)
            link = f"https://github.com/{repo}/blob/{sha}/{f['path']}#L{f['line']}"
            out += [f"### ⚠️ Upgrade risk, not currently broken: [`{f['path']}:{f['line']}`]({link})", "",
                    f"{(f.get('limitations') or [''])[0]}", ""]
            if snip:
                out += [f"```{LANG.get(f['path'].rsplit('.', 1)[-1], '')}", snip, "```", ""]
    return out


def summary_lines(c):
    ch = c["change"]
    before_pass, before_fail = _cases((c["proof"] or {}).get("run"))
    after_pass, after_fail = _cases((c["accepted"] or {}).get("tests"))
    files = sorted({f["path"] for f in c["impacted"]})
    if c["kind"] == "vulnerability":
        pkg = c["group"]["package"]
        what = (f"`{pkg['name']} {pkg['version']}` is affected by **{ch.get('cve') or ch['change_id']}** ({ch.get('title')}), "
                f"and it is called with untrusted input in {len(c['impacted'])} place(s).")
        sev = f"**Severity:** {ch.get('severity', 'n/a')} (advisory)"
    else:
        what = (f"Stripe API `{ch.get('api_version')}` removed {', '.join(f'`{s}`' for s in ch.get('removed_symbols', []))}. "
                f"{len(c['impacted'])} code path(s) in {len(files)} file(s) still read them, so on `{ch.get('api_version')}` payloads they get "
                "`undefined` (renewal dates, invoice previews and webhook access windows become `Invalid Date`).")
        sev = "**Severity:** High (breaking API change on billing paths)"
    proof = (f"**Confidence:** Confirmed: {len(before_fail)} regression test(s) fail on the unpatched code"
             + (f"; **{len(after_pass)}/{len(after_pass) + len(after_fail)}** pass with the accepted fix." if c["accepted"] else "."))
    return [what, "", f"{sev} · {proof}"]


def affected_table(c):
    repo, sha = c["repo"], c["scan_sha"]
    rows = ["| Location | Vulnerable expression | Why it's affected |", "|---|---|---|"]
    for f in c["impacted"]:
        sg = f.get("semgrep") or {}
        gate = f.get("version_gate") or {}
        if gate.get("api_version"):
            why = f"receives `{gate['api_version']}` ({gate.get('basis', '')})"
        elif gate.get("installed"):
            why = f"`{gate['installed']}` is in the affected range ({gate.get('rule', '')})"
        else:
            why = gate.get("rule") or ""
        rows.append(f"| [`{f['path']}:{f['line']}`]({_link(repo, sha, f['path'], f['line'])}) | `{sg.get('matched_code', '').strip()[:90]}` | {why} |")
    out = rows
    if c["others"]:
        out += ["", "**Not changed** (deliberately):"]
        for f in c["others"]:
            out.append(f"- `{f['path']}:{f['line']}` is {f['confidence_tier'].replace('_', ' ')}: {(f.get('limitations') or [''])[0]}")
    return out


def evidence_block(c):
    ch = c["change"]
    sg = (c["impacted"][0].get("semgrep") or {}) if c["impacted"] else {}
    _, before_fail = _cases((c["proof"] or {}).get("run"))
    lines = []
    if c["kind"] == "vulnerability":
        osv = ch.get("source_url")
        lines.append(f"- **Advisory:** [{ch['change_id']}]({osv})" + (f" · [{ch['cve']}](https://nvd.nist.gov/vuln/detail/{ch['cve']})" if ch.get("cve") else ""))
        lines.append(f"- **Version check:** {c['group'].get('version_check', {}).get('reason', '')}")
    else:
        lines.append(f"- **Official changelog:** [{ch.get('title')}]({ch['source_url']})"
                     + (f" · snapshot sha256 `{ch['content_sha256'][:12]}`" if ch.get("content_sha256") else ""))
    if sg:
        lines.append(f"- **Semgrep:** `{sg.get('rule_id')}` matched {len(c['impacted'])} location(s)")
    if before_fail:
        lines.append(f"- **Failing regression tests on the unpatched code ({len(before_fail)}):** " + ", ".join(f"`{t['name']}`" for t in before_fail[:4])
                     + (" …" if len(before_fail) > 4 else ""))
    return lines


def action_checklist(c):
    apps = sorted({_app(f["path"]) for f in c["impacted"]})
    items = [f"- [ ] Review the {len(c['impacted'])} affected location(s) listed above"]
    items += [f"- [ ] Run tests: `{TEST_CMD.get(a, 'run the app test suite')}`" for a in apps]
    if c["kind"] == "vulnerability":
        plan = (c["rem"] or {}).get("upgrade_plan") or {}
        if plan.get("chosen"):
            items.append(f"- [ ] Confirm `{plan.get('package')}` resolves to `{plan['chosen']}` in the lockfile/manifest (OSV: no known advisories at scan time)")
        items.append("- [ ] Confirm the untrusted-input path now rejects the regression probe")
    else:
        items.append(f"- [ ] Validate against a Stripe **test-mode** account on `{c['change'].get('api_version')}`")
        if any(f["confidence_tier"] == "upgrade_risk" for f in c["others"]):
            items.append("- [ ] Migrate the pinned legacy webhook endpoint before upgrading its API version")
    items += ["- [ ] Deploy through the normal release process and monitor errors on the affected paths",
              "- [ ] Merge manually after review (DriftGuard never merges)"]
    return items


def agent_prompt(c):
    ch, repo = c["change"], c["repo"]
    apps = sorted({_app(f["path"]) for f in c["impacted"]})
    locs = "\n".join(f"- {f['path']}:{f['line']}: `{(f.get('semgrep') or {}).get('matched_code', '').strip()[:120]}`" for f in c["impacted"])
    keep = "\n".join(f"- {f['path']}:{f['line']} ({f['confidence_tier'].replace('_', ' ')}): leave unchanged" for f in c["others"])
    tests = "\n".join(f"- `{TEST_CMD.get(a, '')}`" for a in apps)
    reg = [p for p in ((c["accepted"] or {}).get("changed_files") or []) if "/tests/" in p]
    if c["kind"] == "vulnerability":
        pkg = c["group"]["package"]
        plan = (c["rem"] or {}).get("upgrade_plan") or {}
        context_txt = (f"{pkg['name']} {pkg['version']} (from {pkg['manifest']}) is affected by {ch.get('cve') or ch['change_id']}: {ch.get('title')}.\n"
                       f"Advisory: {ch['source_url']}\nAffected range check: {c['group'].get('version_check', {}).get('reason', '')}\n"
                       f"Target: a version outside the affected range with no known OSV advisories"
                       + (f" (DriftGuard verified `{plan['chosen']}`; `{plan.get('minimal_fix_for_target')}` fixes this CVE but still has other advisories)." if plan.get("chosen") else "."))
        expected = "Untrusted input can no longer trigger the vulnerable behavior, and all existing functional behavior is unchanged."
    else:
        context_txt = (f"Stripe API {ch.get('api_version')} removed {', '.join(ch.get('removed_symbols', []))}. Billing periods now live on "
                       f"subscription items ({', '.join(ch.get('added_symbols', []))}).\nSource: {ch['source_url']}\n"
                       "Versions: the billing client sets apiVersion 2025-03-31.basil (apps/billing-ts/src/stripe/client.ts, stripe-node 18.0.0). "
                       "Webhook endpoint /webhooks/stripe receives basil payloads; /webhooks/stripe-legacy is pinned to 2024-12-18.acacia.")
        expected = ("Period dates come from the subscription item that carries the plan price (PRIMARY_PRICE_ID), never blindly from items.data[0]. "
                    "Payloads from endpoints still pinned to older API versions (which keep subscription-level fields) continue to work.")
    return f"""Repository: {repo} (scanned at {c['scan_sha'][:7]})
Task: fix the confirmed {'vulnerability' if c['kind'] == 'vulnerability' else 'breaking API change'} below with the smallest safe change.

Context:
{context_txt}

Affected code (exact Semgrep matches):
{locs}
{('Do not change:' + chr(10) + keep) if keep else ''}

Expected behavior:
{expected}

Required tests (all must pass):
{tests}
{('- Keep or add the regression tests: ' + ', '.join(reg)) if reg else ''}

Constraints:
- Preserve backwards compatibility and existing behavior; keep the existing tests passing.
- Touch only the affected files (plus a minimal helper or test if needed). No unrelated edits, refactors or formatting changes.
- Do not add new dependencies beyond the version change required.
- Never merge, push to main, or deploy. Open or update a draft PR for human review and paste the test output."""


def verification_block(c):
    if not c["accepted"]:
        return ["No verified patch yet."]
    bp, bf = _cases((c["proof"] or {}).get("run"))
    ap, af = _cases(c["accepted"].get("tests"))
    lines = ["| Stage | Result |", "|---|---|",
             f"| Before (unpatched + regression tests) | {len(bp)} ✅ pass · {len(bf)} ❌ fail |",
             f"| After (accepted patch, full suite) | {len(ap)} ✅ pass · {len(af)} ❌ fail |"]
    for a in c["rejected"]:
        reason = a["reason"]
        if reason.startswith("tests failed:"):
            reason = f"{len(reason.split(';'))} tests failed (incl. `{reason[len('tests failed: '):].split(';')[0].strip()}`)"
        lines.append(f"| Rejected `{a['candidate']}` | {reason[:140]} |")
    lines.append(f"| Accepted `{c['accepted']['candidate']}` | {c['accepted'].get('reason', '')[:160]} |")
    if c["ci"]:
        ok = sum(1 for x in c["ci"]["checks"] if x["conclusion"] == "success")
        lines.append(f"| CI on PR head `{c['ci']['head_sha'][:7]}` | {ok}/{len(c['ci']['checks'])} checks passed ({', '.join(x['name'] for x in c['ci']['checks'])}) |")
    return lines


def reviewer_checklist(c):
    if c["kind"] == "vulnerability":
        code = "- [ ] **Code:** the upgrade/loader change is minimal and the untrusted-input path is covered by the regression test"
        ver = "- [ ] **Versions:** the lockfile/manifest resolves to the accepted version; no unrelated dependency changes"
    else:
        code = "- [ ] **Code:** periods are read from the plan's subscription item; subscription-level fallback only for older pinned payloads"
        ver = "- [ ] **Versions:** client `apiVersion` and each webhook endpoint's API version match what this code expects"
    return [code, "- [ ] **Tests:** CI is green and the DriftGuard regression tests cover the pre-change and post-change cases", ver,
            "- [ ] **Decision:** approve or request changes (merge stays manual)"]


def traceability(c, extra=None):
    repo = c["repo"]
    rows = []
    if c["issue"]:
        rows.append(f"- **Issue:** #{c['issue']['number']}")
    if c["pr"]:
        rows.append(f"- **PR:** #{c['pr']['number']} ({'opened by the Guild remediator agent' if c['pr'].get('executor') == 'guild' else 'opened via the direct GitHub fallback'})"
                    + (f" · [Guild session]({c['pr']['guild_session_url']})" if c["pr"].get("guild_session_url") else ""))
    rows.append(f"- **Scanned commit:** [`{c['scan_sha'][:7]}`](https://github.com/{repo}/commit/{c['scan_sha']}) · investigation `{c['scan_run']}`")
    if c["latest"] and c["latest"]["commit_sha"] != c["scan_sha"]:
        rows.append(f"- **Re-confirmed** by investigation `{c['latest']['run_id']}` at [`{c['latest']['commit_sha'][:7]}`](https://github.com/{repo}/commit/{c['latest']['commit_sha']})")
    return rows + (extra or [])


def details(summary, body_lines):
    return ["<details>", f"<summary>{summary}</summary>", "", *body_lines, "", "</details>"]


def _fix_and_tests(c):
    out = ["## ✅ Verified Fix & Tests", ""]
    if c["accepted"]:
        out += [f"Accepted approach: **`{c['accepted']['candidate']}`**: {c['accepted'].get('description', '')}", ""]
    out += verification_block(c) + [""]
    if c["proof"] and (c["proof"].get("run") or {}).get("cases"):
        after = {x["name"]: x["status"] for x in ((c["accepted"] or {}).get("tests") or {}).get("cases", [])}
        out += details("All regression test results (before → after)", [
            "| Test | Before | After |", "|---|---|---|",
            *[f"| `{t['name']}` | {'✅' if t['status'] == 'pass' else '❌'} | "
              f"{('✅' if after[t['name']] == 'pass' else '❌') if t['name'] in after else '—'} |" for t in c["proof"]["run"]["cases"]]]) + [""]
    return out


def _provenance(c):
    return ["## 📎 Evidence & Provenance", "", *evidence_block(c), "", *traceability(c)]


def pr_body(c, executor_note, refreshed_note=None):
    out = [f"> {executor_note} Human review required; DriftGuard never merges.", "", "## Summary", *summary_lines(c), "",
           *exact_code_section(c), *_fix_and_tests(c),
           "## ☑️ Action Checklist", "", "**Reviewer**", *reviewer_checklist(c), "", "**Fix → test → deploy**", *action_checklist(c), "",
           *details("🤖 Copy-paste prompt for an AI coding agent (Claude Code / Cursor / Copilot)", ["```text", agent_prompt(c), "```"]), "",
           *_provenance(c)]
    if refreshed_note:
        out += ["", f"<sub>{refreshed_note}</sub>"]
    return "\n".join(out)


def issue_body(c, marker, snippets=None):
    out = [marker, "", "## Summary", *summary_lines(c), "", *exact_code_section(c)]
    if c["accepted"]:
        out += [*_fix_and_tests(c), f"Verified fix: draft PR #{c['pr']['number']}.", ""]
    out += ["## ☑️ Action Checklist", "", *action_checklist(c), "",
            *details("🤖 Copy-paste prompt for an AI coding agent (Claude Code / Cursor / Copilot)", ["```text", agent_prompt(c), "```"]), "",
            *_provenance(c), "", "---",
            f"<sub>Filed by DriftGuard via the GitHub API (operator token) · updated {datetime.now(timezone.utc).strftime('%Y-%m-%d')} · "
            "only Semgrep-matched lines with a reproduced regression are filed; re-scans update this issue instead of opening a new one.</sub>"]
    return "\n".join(out)
