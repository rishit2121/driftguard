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


OUTPUT_EVENTS = "user_message,agent_notification_message,agent_notification_error"
# runtime_done payloads carry full tool responses (e.g. whole lockfiles) and make the events API slow, so the trace
# is built from runtime_start events (tool-call arguments) only.
TRACE_EVENTS = "runtime_start,agent_console"


def tool_trace(items: list[dict]) -> list[dict]:
    """Pair runtime_start/runtime_done events into a compact tool-call trace (args summary + duration)."""
    calls, open_calls = [], []
    for e in sorted(items, key=lambda x: x.get("created_at", "")):
        kind = e.get("entity_type", "")
        content = e.get("content")
        keys = set(content) if isinstance(content, dict) else set()
        if kind == "EntEventRuntimeStart" and keys and keys != {"text", "type"} and keys != {"level", "message"}:
            if "url" in content:
                summary = f"fetch {content.get('method', 'GET')} {content['url']}"
            elif "tree_sha" in content:
                summary = f"github git tree {content.get('tree_sha', '')[:7]}"
            elif "path" in content:
                summary = f"github contents {content['path']}"
            elif "branch" in content and "commit_sha" not in content:
                summary = f"github branch {content.get('owner')}/{content.get('repo')}@{content['branch']}"
            else:
                summary = "tool " + ",".join(sorted(content)[:5])
            open_calls.append({"call": summary, "started": e.get("created_at")})
        elif kind == "EntEventRuntimeDone" and open_calls and keys and keys != {"result"} and keys != {"text", "type"}:
            call = open_calls.pop(0)
            call["finished"] = e.get("created_at")
            calls.append(call)
    calls.extend(open_calls)
    for c in calls:
        try:
            from datetime import datetime
            c["ms"] = round((datetime.fromisoformat(c["finished"]) - datetime.fromisoformat(c["started"])).total_seconds() * 1000) if c.get("finished") else None
        except Exception:  # noqa: BLE001
            c["ms"] = None
    return calls


def run_session(agent: str, payload: dict, timeout_s: int = config.GUILD_TIMEOUT_S, on_created=None) -> dict:
    """Create a Guild session for `agent`, wait for its root task, and return its output + trace."""
    t0 = time.time()
    created = _json(_guild("session", "create", "--agent", agent, "--prompt", json.dumps(payload), timeout=60))
    session_id = created["id"]
    if on_created:
        on_created(session_id, created.get("session_url"))
    info = created
    while time.time() - t0 < timeout_s:
        info = _json(_guild("session", "get", session_id, timeout=30))
        if str((info.get("root_task") or {}).get("status", "")).upper() in TERMINAL:
            break
        time.sleep(2)
    else:
        raise TimeoutError(f"Guild session {info.get('session_url') or session_id} still running after {timeout_s}s")
    events = _json(_guild("session", "events", session_id, "--events", OUTPUT_EVENTS, "--limit", "50", timeout=45)).get("items", [])
    try:
        trace_events = _json(_guild("session", "events", session_id, "--events", TRACE_EVENTS, "--limit", "100", timeout=45)).get("items", [])
    except Exception:  # noqa: BLE001 - the trace is best-effort; the session link always works
        trace_events = []
    output, errors, trace = None, [], []
    for e in sorted(events, key=lambda x: x.get("created_at", "")):
        kind = e.get("entity_type", "")
        data = (e.get("content") or {}).get("data") if isinstance(e.get("content"), dict) else None
        if kind in ("EntEventAgentNotificationMessage", "EntEventAgentConsole") or "Error" in kind:
            trace.append({"type": kind, "at": e.get("created_at"), "data": (data or e.get("content") or "")[:400] if isinstance(data or e.get("content"), str) else data})
        if kind == "EntEventAgentNotificationMessage" and isinstance(data, str):
            try:
                output = json.loads(data)
            except json.JSONDecodeError:
                pass
        if "Error" in kind:
            errors.append(data)
    return {"session_id": session_id, "session_url": info.get("session_url") or created.get("session_url"),
            "status": (info.get("root_task") or {}).get("status"), "output": output, "errors": errors, "trace": trace,
            "tool_calls": tool_trace(trace_events), "agent_runtime_s": _span_s(trace_events),
            "elapsed_s": round(time.time() - t0, 1)}


def _span_s(items):
    from datetime import datetime
    ts = sorted(e["created_at"] for e in items if e.get("created_at"))
    return round((datetime.fromisoformat(ts[-1]) - datetime.fromisoformat(ts[0])).total_seconds(), 1) if len(ts) > 1 else None


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


def run_watcher(repo: str, branch: str, on_created=None) -> dict:
    return run_session(config.GUILD_WATCHER_AGENT, {"repo": repo, "branch": branch,
                                                    "stripe_changelog_urls": config.STRIPE_CHANGELOG_URLS},
                       on_created=on_created)
