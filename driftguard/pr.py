"""Draft pull request: evidence-backed body + execution via the Guild remediation agent (or disclosed fallback)."""
import subprocess
from pathlib import Path

from . import config, github, guild_bridge


def _case_table(run: dict) -> str:
    rows = ["| Test | Result |", "|---|---|"]
    for c in run["cases"]:
        icon = {"pass": "✅ PASS", "fail": "❌ FAIL", "skipped": "⏭ skip"}[c["status"]]
        rows.append(f"| `{c['name']}` | {icon} |")
    return "\n".join(rows)


def build_body(state: dict, group: dict, result: dict, proof: dict | None, base_sha: str, executor_note: str) -> str:
    change = group["change"]
    repo = state["repo"]
    accepted = result["accepted"]
    impacted = [f for f in group["findings"] if f["status"] == "impacted"]
    others = [f for f in group["findings"] if f["status"] != "impacted"]
    lines = [
        f"> 🤖 Draft opened by **DriftGuard**. {executor_note} Human review and approval are required; this PR will never be merged automatically.",
        "",
        "## Upstream change",
        f"- **Source:** [{change.get('title') or change['change_id']}]({change['source_url']})",
    ]
    if group["kind"] == "vulnerability":
        lines += [f"- **Advisory:** {change['change_id']} ({change.get('cve')}) — severity {change.get('severity')}",
                  f"- **OSV IDs:** {', '.join(group.get('osv_ids') or [])}",
                  f"- **Installed:** `{group['package']['name']} {group['package']['version']}` from `{group['package']['manifest']}` "
                  f"({group['package']['version_source']})"]
    else:
        lines += [f"- **Affected API versions:** {', '.join(change.get('affected_api_versions') or [])}",
                  f"- **Removed:** {', '.join(f'`{s}`' for s in change.get('removed_symbols', []))}",
                  f"- **Replacement:** {', '.join(f'`{s}`' for s in change.get('added_symbols', []))}"]
    if change.get("content_sha256"):
        lines.append(f"- **Source snapshot:** sha256 `{change['content_sha256'][:16]}…` fetched {change.get('fetched_at') or ''} ({change.get('source_mode', 'live')})")
    lines += ["", f"## Affected code (scanned at `{base_sha}`)", "| Location | Evidence | Why impacted | Tier |", "|---|---|---|---|"]
    for f in impacted:
        url = f"https://github.com/{repo}/blob/{base_sha}/{f['path']}#L{f['line']}-L{f['end_line']}"
        why = f.get("version_gate", {}).get("rule") or ""
        if f.get("version_gate", {}).get("basis"):
            why += f" — {f['version_gate']['basis']}"
        lines.append(f"| [{f['path']}:{f['line']}]({url}) | `{(f.get('semgrep') or {}).get('rule_id', '')}` `{f['symbol']}` | {why} | {f['confidence_tier']} |")
    if others:
        lines += ["", "**Not changed by this PR:**"]
        for f in others:
            lines.append(f"- `{f['path']}:{f['line']}` — {f['status']} ({f['confidence_tier']}): {(f.get('limitations') or [''])[0]}")
    lines += ["", "## Change", f"**Accepted candidate:** `{accepted['candidate']}` — {accepted['description']}",
              f"- Acceptance check: {accepted['reason']}", "- Files: " + ", ".join(f"`{p}`" for p in accepted["changed_files"])]
    plan = result.get("upgrade_plan")
    if plan:
        lines += ["", f"**Upgrade selection** ({plan['policy']}): `{plan['current']}` → `{plan['chosen']}`; "
                  f"{plan['candidates_checked']} newer versions checked against OSV."]
        if plan.get("minimal_fix_for_target") and plan["minimal_fix_remaining_advisories"]:
            lines.append(f"- The minimal fix `{plan['minimal_fix_for_target']}` would still be affected by "
                         f"{len(plan['minimal_fix_remaining_advisories'])} other advisories ({', '.join(plan['minimal_fix_remaining_advisories'])}) — not chosen.")
    lines += ["", "## Verification"]
    if proof and proof.get("run"):
        lines += ["**Before (unpatched code + DriftGuard regression tests):**", "", _case_table(proof["run"]), ""]
    lines += ["**After (accepted patch, full suite):**", "", _case_table(accepted["tests"]), ""]
    rejected = [a for a in result["attempts"] if a["verdict"] == "rejected"]
    if rejected:
        lines += ["**Rejected candidates** (a fix must pass the security/contract tests *and* every existing test):"]
        for a in rejected:
            lines.append(f"- `{a['candidate']}` — {a['description']}: **rejected**, {a['reason']}")
    lines += ["", "## Limitations", *[f"- {l}" for l in sorted({l for f in impacted for l in f.get('limitations', [])})],
              "- Fixtures are synthetic objects shaped after the documented API; validate against a Stripe test-mode account before merging." if group["kind"] != "vulnerability" else
              "- Tests use inert probes only; no exploit payload was executed.",
              "", "## Rollback", "Revert this PR. No data migrations or configuration changes are included.",
              "", f"<sub>DriftGuard run `{state['run_id']}` · repo `{repo}` · base `{base_sha}` · Guild/ClickHouse/Akash/Semgrep evidence in the DriftGuard UI.</sub>"]
    return "\n".join(lines)


def open_pull_request(state: dict, group: dict, result: dict, proof: dict | None, base_sha: str) -> dict:
    wt = Path(result["accepted"]["worktree"])
    branch = f"driftguard/{result['playbook']}-{base_sha[:7]}"
    title = result["pr_title"]
    github.git("checkout", "-q", "-B", branch, cwd=wt)
    github.git("add", "-A", "--", ".", ":(exclude)**/node_modules/**", cwd=wt)
    subprocess.run(["git", "-c", "user.name=DriftGuard Bot", "-c", "user.email=driftguard-bot@users.noreply.github.com",
                    "commit", "-q", "-m", f"{title}\n\nDriftGuard run {state['run_id']}; source {group['change']['source_url']}"],
                   cwd=wt, check=True, capture_output=True)
    files = {}
    for rel in github.git("diff", "--name-only", f"{base_sha}..HEAD", cwd=wt).splitlines():
        p = wt / rel
        files[rel] = p.read_text() if p.exists() else None

    if config.PR_EXECUTOR == "guild":
        note = "Opened by the **Guild remediation agent** through Guild's GitHub integration."
        body = build_body(state, group, result, proof, base_sha, note)
        out = guild_bridge.open_pr(state["repo"], base_sha, state["branch"], branch, title, body, files)
        return {**out, "branch": branch, "executor": "guild", "body": body}

    note = ("Opened via **direct GitHub API fallback** with the operator's token (Guild GitHub integration not "
            "authorized in this environment).")
    body = build_body(state, group, result, proof, base_sha, note)
    github.push_branch(wt, branch)
    out = github.open_draft_pr(state["repo"], branch, state["branch"], title, body)
    return {**out, "branch": branch, "executor": "github_fallback", "body": body}
