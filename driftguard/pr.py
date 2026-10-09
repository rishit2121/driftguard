"""Draft pull request: evidence-backed body + execution via the Guild remediation agent (or disclosed fallback)."""
import subprocess
from pathlib import Path

from . import config, github, guild_bridge, reporting_md


def _unused_case_table(run: dict) -> str:
    rows = ["| Test | Result |", "|---|---|"]
    for c in run["cases"]:
        icon = {"pass": "✅ PASS", "fail": "❌ FAIL", "skipped": "⏭ skip"}[c["status"]]
        rows.append(f"| `{c['name']}` | {icon} |")
    return "\n".join(rows)


def build_body(state: dict, group: dict, result: dict, proof: dict | None, base_sha: str, executor_note: str) -> str:
    rem = {"attempts": [{**a} for a in result["attempts"]], "accepted": result["accepted"]["candidate"], "pr": None,
           "upgrade_plan": result.get("upgrade_plan"), "diff": result["accepted"].get("diff"), "commit_sha": base_sha, "run_id": state["run_id"]}
    c = reporting_md.context(state, group, group["findings"], rem, proof)
    return reporting_md.pr_body(c, executor_note)


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
