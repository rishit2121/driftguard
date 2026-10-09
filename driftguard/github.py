"""GitHub access: resolve branch -> immutable SHA, snapshot checkout, fix branches, draft PRs, CI status.

Uses the operator's GitHub token (gh CLI) for reads. PR creation goes through the Guild remediation agent when
DRIFTGUARD_PR_EXECUTOR=guild; otherwise this module opens it directly and the PR/UI disclose that fallback.
"""
import os
import subprocess
from functools import lru_cache
from pathlib import Path

import httpx

from . import config

API = "https://api.github.com"


@lru_cache(maxsize=1)
def token() -> str:
    return os.environ.get("GITHUB_TOKEN") or subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True).stdout.strip()


def gh(method: str, path: str, **kw) -> dict | list:
    r = httpx.request(method, f"{API}{path}", headers={"Authorization": f"Bearer {token()}", "Accept": "application/vnd.github+json",
                                                     "X-GitHub-Api-Version": "2022-11-28"}, timeout=30, **kw)
    r.raise_for_status()
    return r.json() if r.content else {}


def git(*args, cwd: Path, check=True) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=check).stdout.strip()


def repo_info(repo: str) -> dict:
    info = gh("GET", f"/repos/{repo}")
    return {"full_name": info["full_name"], "html_url": info["html_url"], "default_branch": info["default_branch"],
            "visibility": info["visibility"], "pushed_at": info["pushed_at"], "description": info.get("description")}


def resolve_sha(repo: str, branch: str) -> str:
    return gh("GET", f"/repos/{repo}/commits/{branch}")["sha"]


def checkout(repo: str, sha: str) -> Path:
    """Read-only snapshot of the repository at exactly `sha`."""
    dest = config.WORK_DIR / "snapshots" / repo.replace("/", "__") / sha
    if (dest / ".git").exists():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    git("init", "-q", cwd=dest)
    git("remote", "add", "origin", f"https://github.com/{repo}.git", cwd=dest)
    git("fetch", "-q", "--depth", "1", "origin", sha, cwd=dest)
    git("checkout", "-q", "FETCH_HEAD", cwd=dest)
    return dest


def worktree(repo: str, sha: str, name: str) -> Path:
    """Isolated writable copy for a remediation attempt (never the snapshot itself)."""
    dest = config.WORK_DIR / "remediation" / name
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    git("clone", "-q", str(checkout(repo, sha)), str(dest), cwd=config.WORK_DIR)
    git("checkout", "-q", sha, cwd=dest)
    git("remote", "set-url", "origin", f"https://github.com/{repo}.git", cwd=dest)
    return dest


def push_branch(path: Path, branch: str):
    url = f"https://x-access-token:{token()}@github.com/" + git("remote", "get-url", "origin", cwd=path).split("github.com/")[1]
    subprocess.run(["git", "push", "-q", "-f", url, f"HEAD:refs/heads/{branch}"], cwd=path, capture_output=True, text=True, check=True)


def open_draft_pr(repo: str, branch: str, base: str, title: str, body: str) -> dict:
    existing = gh("GET", f"/repos/{repo}/pulls", params={"head": f"{repo.split('/')[0]}:{branch}", "state": "open"})
    if existing:
        pr = gh("PATCH", f"/repos/{repo}/pulls/{existing[0]['number']}", json={"title": title, "body": body})
    else:
        pr = gh("POST", f"/repos/{repo}/pulls", json={"title": title, "head": branch, "base": base, "body": body, "draft": True})
    return {"url": pr["html_url"], "number": pr["number"], "draft": pr["draft"], "head_sha": pr["head"]["sha"]}


def check_runs(repo: str, sha: str) -> list[dict]:
    data = gh("GET", f"/repos/{repo}/commits/{sha}/check-runs")
    return [{"name": c["name"], "status": c["status"], "conclusion": c["conclusion"], "url": c["html_url"]}
            for c in data.get("check_runs", [])]


def pr_status(repo: str, number: int) -> dict:
    pr = gh("GET", f"/repos/{repo}/pulls/{number}")
    return {"url": pr["html_url"], "state": pr["state"], "draft": pr["draft"], "merged": pr["merged"],
            "head_sha": pr["head"]["sha"], "checks": check_runs(repo, pr["head"]["sha"])}
