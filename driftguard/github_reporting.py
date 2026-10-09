"""GitHub Issues + inline PR review comments for CONFIRMED findings (Semgrep file/line evidence only).

- One Issue per confirmed vulnerability / breaking API change group, keyed by a hidden marker so repeated scans update
  the same Issue instead of creating duplicates.
- Inline review comments on the remediation PR, anchored on the exact diff line whose content equals the Semgrep
  match (LEFT side = the removed vulnerable line). For dependency upgrades the vulnerable line is not part of the diff,
  so the comment is anchored on the manifest line that changes the version.
- GitHub has no custom line colors for Issues/PRs; the red/green comes from GitHub's own ```diff highlighting and PR diff.
"""
import hashlib
import json
import re

from . import github, reporting_md, store

LANG = {".ts": "typescript", ".js": "javascript", ".py": "python", ".java": "java", ".json": "json", ".txt": "text", ".xml": "xml"}
LABELS = {"driftguard": "6aa8ff", "confirmed": "d73a4a", "breaking-api": "8a63d2", "vulnerability": "b60205"}


def _key(*parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:12]


def remediation_for(state: dict, group_key: str) -> dict | None:
    """This run's remediation, else the most recent earlier run's remediation for the same change group."""
    g = state["groups"][group_key]
    if g.get("remediation"):
        return {"run_id": state["run_id"], "commit_sha": state["commit_sha"], **g["remediation"], "proof": g.get("proof"),
                "findings": [f for f in state["findings"] if f["group_key"] == group_key]}
    rows = store.client().query(
        "SELECT run_id, commit_sha, summary FROM investigations FINAL WHERE repo={r:String} AND status='complete' "
        "AND position(summary, '\"remediation\"') > 0 ORDER BY started_at DESC LIMIT 20", parameters={"r": state["repo"]}).result_rows
    for run_id, sha, summary in rows:
        data = json.loads(summary)
        prior = (data.get("groups") or {}).get(group_key) or {}
        if run_id != state["run_id"] and prior.get("remediation"):
            return {"run_id": run_id, "commit_sha": sha, **prior["remediation"], "proof": prior.get("proof"),
                    "findings": [f for f in data.get("findings", []) if f["group_key"] == group_key]}
    return None


def _ext(path):
    m = re.search(r"\.[a-z]+$", path)
    return m.group(0) if m else ""


def _diff_hunks(diff: str, path: str) -> list[str]:
    out, cur, in_file = [], None, False
    for line in (diff or "").splitlines():
        if line.startswith("diff --git"):
            in_file = line.endswith(f" b/{path}")
            continue
        if not in_file or line.startswith(("+++", "---", "index ", "new file", "deleted file")):
            continue
        if line.startswith("@@"):
            cur = [line]
            out.append(cur)
        elif cur is not None:
            cur.append(line)
    return ["\n".join(h) for h in out]


def _hunk_for(diff, f):
    needle = (f.get("semgrep") or {}).get("matched_code", "").splitlines()[0].strip() if f.get("semgrep") else ""
    hunks = _diff_hunks(diff, f["path"])
    return next((h for h in hunks if any(l.startswith("-") and l[1:].strip() == needle for l in h.splitlines())), hunks[0] if hunks else None)


def _manifest_hunks(diff):
    paths = re.findall(r"^diff --git a/(\S+) b/\S+$", diff or "", re.M)
    return [(p, h) for p in paths if re.search(r"package\.json$|requirements[^/]*\.txt$|pom\.xml$", p) for h in _diff_hunks(diff, p)[:1]]


def _permalink(repo, sha, path, a, b=None):
    return f"https://github.com/{repo}/blob/{sha}/{path}#L{a}" + (f"-L{b}" if b and b != a else "")


def issue_title(group) -> str:
    c = group["change"]
    if group["kind"] == "vulnerability":
        return f"[DriftGuard] {c.get('cve') or c['change_id']}: {group['package']['name']} {group['package']['version']} ({c.get('severity')}) - {c.get('title')}"[:250]
    return f"[DriftGuard] Breaking API change: {c.get('title')} (Stripe {c.get('api_version')})"[:250]


def _ci(repo, rem):
    try:
        st = github.pr_status(repo, rem["pr"]["number"])
        return {"head_sha": st["head_sha"], "checks": st["checks"]}
    except Exception:  # noqa: BLE001
        return None


def issue_body(state, group, findings, rem, marker) -> str:
    repo, sha = state["repo"], state["commit_sha"]
    confirmed = [f for f in findings if f["confidence_tier"] == "confirmed"]
    snippets = []
    for f in confirmed:
        code = f["code"]
        a, b = max(f["line"] - 2, code["first_line"]), min(f["end_line"] + 2, code["first_line"] + len(code["lines"]) - 1)
        snippets.append("\n".join([f"**`{f['path']}:{f['line']}`**", _permalink(repo, sha, f["path"], a, b)]))
    c = reporting_md.context(state, group, findings, rem, (rem or {}).get("proof") or group.get("proof"),
                             issue=None, ci=_ci(repo, rem) if rem else None)
    c["scan_sha"], c["scan_run"] = sha, state["run_id"]
    c["impacted"] = confirmed
    c["others"] = [f for f in findings if f["confidence_tier"] != "confirmed" and f["status"] != "exposed"]
    return reporting_md.issue_body(c, marker, snippets)


def refresh_pr_description(state, group_key, issue=None) -> dict:
    """Rewrite an existing DriftGuard PR description in place (code, commits and authorship untouched)."""
    group = {**state["groups"][group_key], "key": group_key}
    rem = remediation_for(state, group_key)
    if not rem:
        return {"skipped": "no remediation PR"}
    repo = state["repo"]
    c = reporting_md.context(state, group, rem.get("findings") or [], rem, rem.get("proof"), issue=issue, ci=_ci(repo, rem),
                             latest={"run_id": state["run_id"], "commit_sha": state["commit_sha"]})
    note = ("Opened by the **Guild remediator agent** through Guild's GitHub integration." if rem["pr"].get("executor") == "guild"
            else "Opened by **DriftGuard** via the direct GitHub API fallback (operator token).")
    from datetime import datetime, timezone
    refreshed = (f"Description refreshed by DriftGuard via the GitHub API (operator token) on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}. "
                 "Code, commits and PR authorship are unchanged.")
    body = reporting_md.pr_body(c, note, refreshed)
    pr = github.gh("PATCH", f"/repos/{repo}/pulls/{rem['pr']['number']}", json={"body": body})
    return {"pr": pr["number"], "url": pr["html_url"], "chars": len(body)}


def ensure_labels(repo):
    for name, color in LABELS.items():
        try:
            github.gh("POST", f"/repos/{repo}/labels", json={"name": name, "color": color})
        except Exception:  # noqa: BLE001 - 422 when the label exists
            pass


def _existing(repo, path, marker):
    page = 1
    while page < 6:
        items = github.gh("GET", path, params={"state": "all", "per_page": 100, "page": page, **({"labels": "driftguard"} if "issues" in path else {})})
        for it in items:
            if marker in (it.get("body") or ""):
                return it
        if len(items) < 100:
            return None
        page += 1
    return None


def upsert_issue(state, group, findings, rem) -> dict:
    repo = state["repo"]
    marker = f"<!-- driftguard:issue key={_key(repo, group['key'])} -->"
    body = issue_body(state, group, findings, rem, marker)
    labels = ["driftguard", "confirmed", "vulnerability" if group["kind"] == "vulnerability" else "breaking-api"]
    existing = _existing(repo, f"/repos/{repo}/issues", marker)
    if existing:
        if existing.get("body") == body:
            return {"number": existing["number"], "url": existing["html_url"], "action": "unchanged"}
        issue = github.gh("PATCH", f"/repos/{repo}/issues/{existing['number']}", json={"body": body, "title": issue_title(group)})
        return {"number": issue["number"], "url": issue["html_url"], "action": "updated"}
    ensure_labels(repo)
    issue = github.gh("POST", f"/repos/{repo}/issues", json={"title": issue_title(group), "body": body, "labels": labels})
    return {"number": issue["number"], "url": issue["html_url"], "action": "created"}


def _patch_lines(patch: str):
    """Yield (side, line_no, text) for each changed line of a GitHub file patch."""
    o = n = 0
    for line in (patch or "").splitlines():
        m = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if m:
            o, n = int(m.group(1)), int(m.group(2))
            continue
        if line.startswith("-"):
            yield "LEFT", o, line[1:]
            o += 1
        elif line.startswith("+"):
            yield "RIGHT", n, line[1:]
            n += 1
        else:
            o, n = o + 1, n + 1


def annotate_pr(state, group, findings, rem, issue) -> dict:
    repo, pr = state["repo"], rem["pr"]
    files = {f["filename"]: f.get("patch", "") for f in github.gh("GET", f"/repos/{repo}/pulls/{pr['number']}/files", params={"per_page": 100})}
    existing_bodies = " ".join(c.get("body", "") for c in github.gh("GET", f"/repos/{repo}/pulls/{pr['number']}/comments", params={"per_page": 100}))
    c = group["change"]
    acc = next((a for a in rem["attempts"] if a["candidate"] == rem["accepted"]), {})
    after = (acc.get("tests") or {}).get("cases", [])
    fixed_note = (f"All {len(after)} tests pass on this branch" if after else "Tests pass on this branch") + f"; acceptance check: {acc.get('reason', '')}"
    advisory = f"[{c.get('cve') or c['change_id']}]({c['source_url']})" if group["kind"] == "vulnerability" else f"[Stripe changelog]({c['source_url']})"
    comments, skipped, unmatched = [], 0, []
    confirmed = [f for f in findings if f["confidence_tier"] == "confirmed" and f.get("semgrep")]
    for f in confirmed:
        key = _key(group["key"], f["path"], f["semgrep"]["matched_code"].strip())
        marker = f"<!-- driftguard:pr-comment key={key} -->"
        if marker in existing_bodies:
            skipped += 1
            continue
        needle = f["semgrep"]["matched_code"].splitlines()[0].strip()
        anchor = next(((side, ln) for side, ln, text in _patch_lines(files.get(f["path"], "")) if side == "LEFT" and text.strip() == needle), None)
        if anchor:
            body = (f"{marker}\n🔴 **Vulnerable line** (Semgrep `{f['semgrep']['rule_id']}`, confirmed): "
                    f"{f['semgrep']['message'].split('. ')[0].strip()}.\n\n"
                    f"✅ **Why this patch fixes it:** {acc.get('description', '')}. {fixed_note}.\n\n"
                    f"Source: {advisory} · tracking issue #{issue['number']} · scanned at `{state['commit_sha'][:7]}`")
            comments.append({"path": f["path"], "line": anchor[1], "side": "LEFT", "body": body})
        else:
            unmatched.append(f)
    if unmatched and group["kind"] == "vulnerability":
        key = _key(group["key"], "manifest")
        marker = f"<!-- driftguard:pr-comment key={key} -->"
        pkg = group["package"]["name"].split(":")[-1].lower()
        target = next(((p, ln) for p, patch in files.items() if re.search(r"package\.json$|requirements[^/]*\.txt$|pom\.xml$", p)
                       for side, ln, text in _patch_lines(patch) if side == "RIGHT" and pkg in text.lower()), None)
        if marker in existing_bodies:
            skipped += 1
        elif target:
            locs = ", ".join(f"[`{f['path']}:{f['line']}`]({_permalink(repo, state['commit_sha'], f['path'], f['line'])})" for f in unmatched)
            body = (f"{marker}\n🔴 **Vulnerable dependency use** (confirmed): `{group['package']['name']} {group['package']['version']}` is "
                    f"affected by {advisory} and is called with untrusted input at {locs} (Semgrep `{unmatched[0]['semgrep']['rule_id']}`). "
                    f"That call site is unchanged by this PR.\n\n✅ **Why this patch fixes it:** {acc.get('description', '')}. "
                    f"{acc.get('reason', '')}. {fixed_note.split(';')[0]}.\n\nTracking issue #{issue['number']}")
            comments.append({"path": target[0], "line": target[1], "side": "RIGHT", "body": body})
    if comments:
        review_marker = f"<!-- driftguard:review key={_key(group['key'], 'review', len(comments))} -->"
        github.gh("POST", f"/repos/{repo}/pulls/{pr['number']}/reviews", json={
            "event": "COMMENT", "comments": comments,
            "body": f"{review_marker}\n**DriftGuard review**: {len(comments)} affected line(s) annotated inline. "
                    f"Tracking issue #{issue['number']}. Draft PR: a human must review and merge."})
    return {"pr": pr["number"], "posted": len(comments), "already_present": skipped,
            "anchored": [f"{x['path']}:{x['line']} ({x['side']})" for x in comments]}


def report_run(state: dict, log) -> dict:
    """Upsert Issues and annotate PRs for every group with at least one CONFIRMED finding."""
    results = {}
    for key, group in state.get("groups", {}).items():
        findings = [f for f in state["findings"] if f["group_key"] == key]
        if not any(f["confidence_tier"] == "confirmed" for f in findings):
            continue
        full = {**group, "key": key}
        with log.stage("github_issue", "github") as st:
            rem = remediation_for(state, key)
            issue = upsert_issue(state, full, findings, rem)
            st.details = {"group": key, **issue}
        out = {"issue": issue}
        if rem:
            with log.stage("pr_annotations", "github") as st:
                out["pr_review"] = annotate_pr(state, full, findings, rem, issue)
                st.details = {"group": key, **out["pr_review"]}
        results[key] = out
    return results
