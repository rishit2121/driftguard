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


TERMINAL = {"DONE", "ERROR", "FAILED", "CANCELLED", "COMPLETED"}


def run_session(agent: str, payload: dict, timeout_s: int = 900) -> dict:
    """Create a Guild session for `agent`, wait for its root task, and return its output + trace."""
    t0 = time.time()
    created = _json(_guild("session", "create", "--agent", agent, "--prompt", json.dumps(payload)))
    session_id = created["id"]
    info = created
    while time.time() - t0 < timeout_s:
        info = _json(_guild("session", "get", session_id))
        if str((info.get("root_task") or {}).get("status", "")).upper() in TERMINAL:
            break
        time.sleep(4)
    events = _json(_guild("session", "events", session_id, "--limit", "100")).get("items", [])
    output, errors, trace = None, [], []
    for e in events:
        kind = e.get("entity_type", "")
        data = (e.get("content") or {}).get("data") if isinstance(e.get("content"), dict) else None
        trace.append({"type": kind, "at": e.get("created_at"), "data": (data or "")[:400] if isinstance(data, str) else data})
        if kind == "EntEventAgentNotificationMessage" and isinstance(data, str):
            try:
                output = json.loads(data)
            except json.JSONDecodeError:
                pass
        if "Error" in kind:
            errors.append(data)
    return {"session_id": session_id, "session_url": info.get("session_url") or created.get("session_url"),
            "status": (info.get("root_task") or {}).get("status"), "output": output, "errors": errors, "trace": trace,
            "elapsed_s": round(time.time() - t0, 1)}


def open_pr(repo, base_sha, base_branch, branch, title, body, files) -> dict:
    if not config.GUILD_REMEDIATOR_AGENT:
        raise RuntimeError("GUILD_REMEDIATOR_AGENT is not configured")
    payload = {"repo": repo, "base_sha": base_sha, "base_branch": base_branch, "branch": branch,
               "title": title, "body": body, "files": files}
    session = run_session(config.GUILD_REMEDIATOR_AGENT, payload)
    out = session["output"] or {}
    if not out.get("pr_url"):
        raise RuntimeError(f"Guild remediator session {session['session_url']} returned no PR: {session['errors'][:2]}")
    return {"url": out["pr_url"], "number": out["number"], "draft": True, "head_sha": out.get("commit_sha"),
            "guild_session_id": session["session_id"], "guild_session_url": session["session_url"], "guild_trace": session["trace"]}


def run_watcher(repo: str, branch: str) -> dict:
    return run_session(config.GUILD_WATCHER_AGENT, {"repo": repo, "branch": branch,
                                                    "stripe_changelog_urls": config.STRIPE_CHANGELOG_URLS})
