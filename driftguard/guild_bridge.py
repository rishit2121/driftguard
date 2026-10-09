"""Bridge to the two Guild agents (watcher, remediator) via the Guild CLI.

Agents live in ../guild/. Sessions are created with `guild session create` and their outputs/events are pulled
back with `guild session get/events --mode json` so the trace can be shown next to the finding.
"""
import json
import os
import re
import subprocess
import time

from . import config

ENV = {**os.environ, "GUILD_AUTO_UPDATE": "0"}


def _guild(*args, timeout=120) -> str:
    proc = subprocess.run(["guild", "--mode", "json", "--non-interactive", *args], capture_output=True, text=True, timeout=timeout, env=ENV)
    if proc.returncode != 0:
        raise RuntimeError(f"guild {' '.join(args[:2])} failed: {(proc.stderr or proc.stdout)[-800:]}")
    return proc.stdout


def status() -> dict:
    try:
        proc = subprocess.run(["guild", "auth", "status"], capture_output=True, text=True, timeout=30, env=ENV)
        authed = proc.returncode == 0 and "Not authenticated" not in proc.stdout + proc.stderr
        return {"authenticated": authed, "detail": (proc.stdout + proc.stderr).strip()[-300:],
                "watcher_agent": config.GUILD_WATCHER_AGENT, "remediator_agent": config.GUILD_REMEDIATOR_AGENT,
                "pr_executor": config.PR_EXECUTOR}
    except FileNotFoundError:
        return {"authenticated": False, "detail": "guild CLI not installed", "pr_executor": config.PR_EXECUTOR}


def _json(text: str):
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        lines = [json.loads(l) for l in text.splitlines() if l.strip().startswith("{")]
        return lines[-1] if lines else {}


def run_session(agent: str, payload: dict, timeout_s: int = 900) -> dict:
    created = _json(_guild("session", "create", "--agent", agent, "--prompt", json.dumps(payload)))
    session_id = created.get("id") or created.get("session", {}).get("id")
    deadline = time.time() + timeout_s
    info = created
    while time.time() < deadline:
        info = _json(_guild("session", "get", session_id))
        status = (info.get("root_task") or {}).get("status") or info.get("status")
        if status in ("completed", "complete", "succeeded", "failed", "error", "cancelled"):
            break
        time.sleep(5)
    events = _json(_guild("session", "events", session_id, "--events", "all", "--limit", "200"))
    return {"session_id": session_id, "session_url": info.get("session_url") or created.get("session_url"), "info": info, "events": events}


def _final_output(session: dict) -> dict:
    blob = json.dumps(session["info"]) + json.dumps(session["events"])
    m = re.findall(r'\\?"pr_url\\?"\s*:\s*\\?"(https://github\.com/[^"\\]+)', blob)
    out = {"url": m[-1] if m else None}
    n = re.findall(r"/pull/(\d+)", out["url"] or "")
    out["number"] = int(n[0]) if n else None
    return out


def open_pr(repo, base_sha, base_branch, branch, title, body, files) -> dict:
    if not config.GUILD_REMEDIATOR_AGENT:
        raise RuntimeError("GUILD_REMEDIATOR_AGENT is not configured")
    payload = {"type": "text", "text": json.dumps({"repo": repo, "base_sha": base_sha, "base_branch": base_branch, "branch": branch,
                                                   "title": title, "body": body, "files": files, "draft": True})}
    session = run_session(config.GUILD_REMEDIATOR_AGENT, payload)
    out = _final_output(session)
    if not out["url"]:
        raise RuntimeError(f"Guild remediator session {session['session_id']} returned no PR URL")
    return {**out, "draft": True, "guild_session_id": session["session_id"], "guild_session_url": session["session_url"]}


def run_watcher(repo: str, branch: str) -> dict:
    payload = {"type": "text", "text": json.dumps({"repo": repo, "branch": branch, "stripe_changelog_urls": config.STRIPE_CHANGELOG_URLS})}
    return run_session(config.GUILD_WATCHER_AGENT, payload)
