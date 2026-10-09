"""DriftGuard HTTP API + static UI."""
import json
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import codeindex, config, github, guild_bridge, pipeline, store
from .ml import MLService

app = FastAPI(title="DriftGuard")
WEB = config.ROOT / "web"


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


app.mount("/static", StaticFiles(directory=WEB), name="static")


def _safe(fn):
    t0 = time.perf_counter()
    try:
        return {"ok": True, **fn(), "checked_ms": round((time.perf_counter() - t0) * 1000, 1)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@app.get("/api/status")
def status():
    def ch():
        r = store.client().query("SELECT version(), uptime()")
        return {"version": r.result_rows[0][0], "host": f"{config.CLICKHOUSE_HOST}:{config.CLICKHOUSE_PORT}",
                "database": config.CLICKHOUSE_DATABASE, "cloud": config.CLICKHOUSE_SECURE}

    def sg():
        out = subprocess.run([config.SEMGREP_BIN, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
        return {"version": out, "rules": len(list(config.RULES_DIR.glob("*.yaml")))}

    return {"clickhouse": _safe(ch), "ml": _safe(lambda: MLService().health()), "guild": _safe(guild_bridge.status),
            "github": _safe(lambda: github.repo_info(config.DEMO_REPO)), "semgrep": _safe(sg)}


@app.get("/api/repos")
def repos():
    run_id = pipeline.latest_run_id(config.DEMO_REPO)
    state = pipeline.load_run(run_id) if run_id else None
    info = github.repo_info(config.DEMO_REPO)
    return [{**info, "branch": config.DEMO_BRANCH, "latest_run_id": run_id,
             "last_scan_sha": state.get("commit_sha") if state else None,
             "last_scan_at": state.get("finished_at") if state else None,
             "languages": state["inventory"]["languages"] if state else [],
             "package_count": state["inventory"]["package_count"] if state else None,
             "direct": state["inventory"]["direct"] if state else [],
             "unverified": state["inventory"]["unverified"] if state else [],
             "stripe": state["inventory"]["stripe"] if state else {},
             "counts": state.get("counts") if state else {}}]


class InvestigationRequest(BaseModel):
    repo: str = config.DEMO_REPO
    branch: str = config.DEMO_BRANCH
    prove: bool = True


@app.post("/api/investigations")
def start_investigation(req: InvestigationRequest):
    if req.repo != config.DEMO_REPO:
        raise HTTPException(403, "only the authorized demo repository may be scanned")
    return {"run_id": pipeline.start(req.repo, req.branch, req.prove)}


@app.get("/api/investigations")
def list_investigations():
    rows = store.client().query("SELECT run_id, started_at, commit_sha, status, JSONExtractString(summary, 'duration_ms') "
                                "FROM investigations FINAL WHERE repo={r:String} ORDER BY started_at DESC LIMIT 30",
                                parameters={"r": config.DEMO_REPO}).result_rows
    return [{"run_id": r[0], "started_at": str(r[1]), "commit_sha": r[2], "status": r[3], "duration_ms": r[4]} for r in rows]


@app.get("/api/investigations/latest")
def latest():
    return {"run_id": pipeline.latest_run_id(config.DEMO_REPO)}


def _run(run_id):
    state = pipeline.load_run(run_id)
    if not state:
        raise HTTPException(404, "unknown run")
    return state


@app.get("/api/investigations/{run_id}")
def investigation(run_id: str):
    state = _run(run_id)
    slim = {k: v for k, v in state.items() if k not in ("findings", "groups", "semantic", "proofs", "traceback") and not k.startswith("_")}
    slim["findings"] = [{k: f.get(k) for k in ("finding_id", "group_key", "finding_type", "path", "line", "status", "confidence_tier",
                                                "change_id", "tab", "model_score", "test_status", "pr_url", "symbol")}
                        for f in state.get("findings", [])]
    slim["remediable_groups"] = [k for k, g in state.get("groups", {}).items() if g.get("remediable")]
    slim["pr_by_group"] = {k: g["remediation"]["pr"]["url"] for k, g in state.get("groups", {}).items() if g.get("remediation")}
    return slim


@app.get("/api/investigations/{run_id}/events")
def events(run_id: str):
    state = _run(run_id)
    return {"status": state.get("status"), "error": state.get("error"), "events": [
        {**e, "event_at": str(e["event_at"]), "details": json.loads(e["details"]) if isinstance(e["details"], str) and e["details"].startswith("{") else e["details"]}
        for e in state.get("events", [])]}


@app.get("/api/investigations/{run_id}/groups/{group_key:path}")
def group(run_id: str, group_key: str):
    state = _run(run_id)
    g = state["groups"].get(group_key)
    if not g:
        raise HTTPException(404, "unknown group")
    findings = [f for f in state["findings"] if f["group_key"] == group_key]
    return {"group": g, "findings": findings, "semantic": state.get("semantic", {}).get(g["change"]["change_id"]),
            "rules": state["semgrep"]["rules"], "commit_sha": state["commit_sha"], "repo": state["repo"]}


@app.get("/api/investigations/{run_id}/findings/{finding_id}")
def finding(run_id: str, finding_id: str):
    state = _run(run_id)
    f = next((x for x in state["findings"] if x["finding_id"] == finding_id), None)
    if not f:
        raise HTTPException(404, "unknown finding")
    g = state["groups"].get(f["group_key"])
    rule = state["semgrep"]["rules"].get((f.get("semgrep") or {}).get("rule_id", ""))
    siblings = [{k: x.get(k) for k in ("finding_id", "path", "line", "status", "confidence_tier")} for x in state["findings"]
                if x["group_key"] == f["group_key"] and x["finding_id"] != finding_id]
    prior = prior_remediation(f["group_key"], run_id) if g and not g.get("remediation") else None
    report = (state.get("github_reports") or {}).get(f["group_key"]) or {}
    return {"finding": f, "group": g, "rule": rule, "siblings": siblings, "prior_remediation": prior,
            "issue": report.get("issue"), "pr_review": report.get("pr_review"), "repo": state["repo"], "commit_sha": state["commit_sha"],
            "semantic": state.get("semantic", {}).get(f["change_id"]), "ml": {k: v for k, v in state.get("ml", {}).items() if k != "calls"},
            "quarantine": state.get("quarantine", [])}


class RemediationRequest(BaseModel):
    run_id: str
    group_key: str


@app.post("/api/remediations")
def start_remediation(req: RemediationRequest):
    state = _run(req.run_id)
    g = state["groups"].get(req.group_key)
    if not g or not g.get("remediable"):
        raise HTTPException(400, "group has no reproduced finding with a remediation playbook")
    return {"rem_id": pipeline.start_remediation(req.run_id, req.group_key)}


@app.get("/api/remediations/{rem_id}")
def remediation_status(rem_id: str):
    rem = pipeline.REMEDIATIONS.get(rem_id)
    if not rem:
        raise HTTPException(404, "unknown remediation")
    out = {k: v for k, v in rem.items() if k not in ("events", "result", "traceback")}
    out["events"] = [{**e, "event_at": str(e["event_at"]), "details": json.loads(e["details"])} for e in rem.get("events", [])]
    if rem.get("result"):
        out["attempts"] = [{k: v for k, v in a.items() if k != "diff"} for a in rem["result"]["attempts"]]
    return out


@app.get("/api/pr-status")
def pr_status(url: str):
    parts = url.rstrip("/").split("/")
    repo, number = f"{parts[-4]}/{parts[-3]}", int(parts[-1])
    if repo != config.DEMO_REPO:
        raise HTTPException(403, "not the demo repository")
    return github.pr_status(repo, number)


ANALYTICS = {
    "provider_observations": """
SELECT provider, count() AS observations,
       uniqExact(content_sha256) AS distinct_snapshots,
       max(observed_at) AS latest_observation
FROM source_observations
GROUP BY provider
ORDER BY observations DESC""",
    "corpus": """
SELECT
  (SELECT count() FROM doc_chunks) AS doc_chunks,
  (SELECT uniqExact(change_id) FROM doc_chunks) AS distinct_changes,
  (SELECT uniqExact(affected_version) FROM doc_chunks WHERE affected_version != '') AS distinct_versions,
  (SELECT uniqExact(source_url) FROM source_observations) AS source_pages,
  (SELECT uniqExact(change_id) FROM source_observations WHERE provider = 'osv') AS advisories,
  (SELECT count() FROM code_symbols) AS code_vectors,
  (SELECT uniqExact(commit_sha) FROM code_symbols) AS indexed_commits""",
    "findings_by_tier": """
SELECT confidence_tier, status, count() AS findings, uniqExact(path) AS files
FROM (SELECT finding_id, argMax(confidence_tier, observed_at) AS confidence_tier, argMax(status, observed_at) AS status,
             argMax(path, observed_at) AS path FROM findings WHERE repo = {repo:String} GROUP BY finding_id)
GROUP BY confidence_tier, status ORDER BY findings DESC""",
    "match_types": """
SELECT countIf(semgrep_rule != '') AS exact_code_matches, countIf(semgrep_rule = '') AS inventory_only,
       countIf(model_score >= 0.75) AS ranker_impacted, countIf(model_score > 0 AND model_score < 0.35) AS ranker_unaffected,
       countIf(pr_url != '') AS with_pr
FROM (SELECT finding_id, argMax(semgrep_rule, observed_at) AS semgrep_rule, argMax(model_score, observed_at) AS model_score,
             argMax(pr_url, observed_at) AS pr_url FROM findings WHERE repo = {repo:String} GROUP BY finding_id)""",
    "query_latency": """
SELECT query_name, count() AS runs, round(quantile(0.5)(elapsed_ms), 2) AS p50_ms, round(quantile(0.95)(elapsed_ms), 2) AS p95_ms,
       round(avg(rows_read)) AS avg_rows_read
FROM query_latency GROUP BY query_name ORDER BY runs DESC""",
    "stage_latency": """
SELECT stage, provider, count() AS runs, round(quantile(0.5)(duration_ms)) AS p50_ms, round(quantile(0.95)(duration_ms)) AS p95_ms
FROM run_events GROUP BY stage, provider ORDER BY p50_ms DESC LIMIT 25""",
    "observation_timeline": """
SELECT toDate(observed_at) AS day, provider, count() AS observations, uniqExact(content_sha256) AS distinct_snapshots
FROM source_observations WHERE observed_at >= now() - INTERVAL 30 DAY
GROUP BY day, provider ORDER BY day, provider""",
    "dedupe": """
SELECT source_url, count() AS fetches, uniqExact(content_sha256) AS distinct_versions,
       min(observed_at) AS first_seen, max(observed_at) AS last_seen
FROM source_observations WHERE provider IN ('stripe', 'osv')
GROUP BY source_url HAVING fetches > 1 ORDER BY distinct_versions DESC, fetches DESC LIMIT 12""",
}


@app.get("/api/analytics")
def analytics():
    out = {}
    for name, sql in ANALYTICS.items():
        res = store.timed_query(f"analytics_{name}", sql.strip(), {"repo": config.DEMO_REPO})
        out[name] = {"columns": res["columns"], "rows": [[str(c) if not isinstance(c, (int, float)) else c for c in r] for r in res["rows"]],
                     "stats": res["stats"], "sql": sql.strip()}
    return out


class VectorRequest(BaseModel):
    run_id: str
    change_id: str


@app.post("/api/sql/vector")
def vector(req: VectorRequest):
    state = _run(req.run_id)
    g = next((g for g in state["groups"].values() if g["change"]["change_id"] == req.change_id), None)
    if not g:
        raise HTTPException(404, "unknown change")
    ml = MLService()
    res = codeindex.retrieve(g["change"], state["repo"], state["commit_sha"], ml, req.run_id)
    rows = store.rows_as_dicts(res["filtered"])
    for r in rows:
        r.pop("usage_context", None)
    return {"sql": res["filtered"]["sql"], "stats": res["filtered"]["stats"], "rows": rows, "ml_calls": ml.calls,
            "params": {"repo": state["repo"], "sha": state["commit_sha"], "package": g["change"].get("package"),
                       "change_vector": f"Array(Float32)[{len(res['vector'])}] from {ml.calls[0]['model_version'] if ml.calls else '?'}"}}


# ----------------------------------------------------------------------------- demo support

_PRIOR_CACHE: dict = {}


def prior_remediation(group_key: str, exclude_run: str) -> dict | None:
    """Most recent remediation (draft PR) for the same change group from an EARLIER run, labeled with its run + SHA."""
    if group_key in _PRIOR_CACHE:
        return _PRIOR_CACHE[group_key]
    rows = store.client().query(
        "SELECT run_id, commit_sha, summary FROM investigations FINAL WHERE repo={r:String} AND status='complete' "
        "AND position(summary, '\"remediation\"') > 0 ORDER BY started_at DESC LIMIT 20", parameters={"r": config.DEMO_REPO}).result_rows
    for run_id, sha, summary in rows:
        if run_id == exclude_run:
            continue
        g = (json.loads(summary).get("groups") or {}).get(group_key) or {}
        if g.get("remediation"):
            out = {"run_id": run_id, "commit_sha": sha, **g["remediation"], "proof": g.get("proof")}
            _PRIOR_CACHE[group_key] = out
            return out
    return None


def _after_counts(rem):
    acc = next((a for a in rem.get("attempts", []) if a.get("verdict") == "accepted"), None)
    cases = ((acc or {}).get("tests") or {}).get("cases", [])
    return {"pass": sum(c["status"] == "pass" for c in cases), "fail": sum(c["status"] == "fail" for c in cases)} if cases else None


def _plan_summary(plan):
    if not plan:
        return None
    return {"current": plan.get("current"), "chosen": plan.get("chosen"), "minimal_fix": plan.get("minimal_fix_for_target"),
            "minimal_fix_remaining": len(plan.get("minimal_fix_remaining_advisories") or []),
            "chosen_remaining": len(plan.get("chosen_remaining_advisories") or []), "checked": plan.get("candidates_checked")}


def _median(xs):
    xs = sorted(x for x in xs if x is not None)
    return xs[len(xs) // 2] if xs else None


@app.get("/api/overview")
def overview(run_id: str | None = None):
    run_id = run_id or pipeline.latest_run_id(config.DEMO_REPO)
    state = _run(run_id)
    groups, findings = state.get("groups", {}), state.get("findings", [])
    ml = state.get("ml", {})
    calls = ml.get("calls", [])
    gw = state.get("guild_watcher") or {}
    gw_event = next((e for e in state.get("events", []) if e.get("stage") == "guild_watcher"), None)
    gw_details = json.loads(gw_event["details"]) if gw_event and isinstance(gw_event.get("details"), str) else (gw_event or {}).get("details") or {}

    def group_card(key):
        g = groups[key]
        fs = [f for f in findings if f["group_key"] == key]
        rem = g.get("remediation")
        source = "this run"
        if not rem:
            rem = prior_remediation(key, run_id)
            source = f"earlier run {rem['run_id']} @ {rem['commit_sha'][:7]}" if rem else None
        proof = g.get("proof") or {}
        cases = (proof.get("run") or {}).get("cases", [])
        return {
            "issue": ((state.get("github_reports") or {}).get(key) or {}).get("issue"),
            "group_key": key, "kind": g["kind"], "title": g["change"].get("title"), "change_id": g["change"]["change_id"],
            "cve": g["change"].get("cve"), "source_url": g["change"]["source_url"], "package": (g.get("package") or {}).get("name"),
            "installed": (g.get("package") or {}).get("version"),
            "locations": [{"finding_id": f["finding_id"], "path": f["path"], "line": f["line"], "tier": f["confidence_tier"], "status": f["status"]} for f in fs],
            "proof": {"status": proof.get("status"), "pass": sum(c["status"] == "pass" for c in cases),
                      "fail": sum(c["status"] == "fail" for c in cases), "failing": [c["name"] for c in cases if c["status"] == "fail"]},
            "remediation": {"source": source, "pr": rem.get("pr"), "accepted": rem.get("accepted"),
                            "attempts": [{k: a.get(k) for k in ("candidate", "description", "verdict", "reason")} for a in rem.get("attempts", [])],
                            "after": _after_counts(rem), "upgrade_plan": _plan_summary(rem.get("upgrade_plan"))} if rem else None,
        }

    headline = next((k for k, g in groups.items() if g["kind"] == "breaking_api" and g.get("remediable")), None)
    security = [k for k, g in groups.items() if g["kind"] == "vulnerability" and any(
        f["group_key"] == k and f["status"] in ("impacted", "potentially_affected") for f in findings)]
    sem = (state.get("semantic") or {}).get(groups[headline]["change"]["change_id"]) if headline else None
    return {
        "run": {k: state.get(k) for k in ("run_id", "repo", "branch", "commit_sha", "started_at", "finished_at", "duration_ms", "status", "counts")},
        "fallback_run_id": config.FALLBACK_RUN_ID or None,
        "headline": group_card(headline) if headline else None,
        "security": [group_card(k) for k in security],
        "evidence": {
            "guild": {"session_url": gw.get("session_url") or gw_details.get("session_url"), "status": gw.get("status"),
                      "elapsed_s": gw.get("elapsed_s"), "tool_calls": gw.get("tool_calls") or [], "sha_agrees": gw_details.get("sha_agrees"),
                      "commit_sha": (gw.get("output") or {}).get("commit_sha"), "package_count": (gw.get("output") or {}).get("package_count"),
                      "stripe_hash_agrees": next((g["change"].get("guild_hash_agrees") for g in groups.values() if g["kind"] == "breaking_api"), None)},
            "akash": {"health": ml.get("health"), "calls": len(calls), "median_roundtrip_ms": _median([c["roundtrip_ms"] for c in calls]),
                      "median_server_ms": _median([c.get("server_ms") for c in calls]), "error": ml.get("error")},
            "clickhouse": {"vector_stats": (sem or {}).get("stats"), "baseline_stats": (sem or {}).get("unfiltered_stats"),
                           "candidates": len((sem or {}).get("filtered_rows", []))},
            "semgrep": {k: state.get("semgrep", {}).get(k) for k in ("version", "elapsed_ms", "results")},
        },
        "quarantine": state.get("quarantine", []),
    }


@app.get("/api/benchmark")
def benchmark(run_id: str | None = None):
    """Score a run with the demo repo's own evaluation harness (benchmark/ at the scanned SHA)."""
    run_id = run_id or pipeline.latest_run_id(config.DEMO_REPO)
    state = _run(run_id)
    src = config.WORK_DIR / "snapshots" / state["repo"].replace("/", "__") / state["commit_sha"] / "benchmark"
    if not (src / "run_benchmark.py").exists():
        raise HTTPException(404, "benchmark harness not present at this commit")
    dest = config.WORK_DIR / "benchmark" / run_id
    import shutil
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src, dest)
    proc = subprocess.run(["python3", str(dest / "run_benchmark.py"), "--api", "http://127.0.0.1:8080", "--run", run_id],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise HTTPException(500, proc.stderr[-800:])
    report = json.loads((dest / "benchmark_report.json").read_text())
    report["scenario_titles"] = {}
    try:
        import yaml
        sc = yaml.safe_load((dest / "scenarios.yaml").read_text())
        report["scenario_titles"] = {s["id"]: s["title"] for s in sc.get("scenarios", [])}
        report["edge_case_titles"] = {str(k): v for k, v in (sc.get("edge_cases") or {}).items()}
    except Exception:  # noqa: BLE001
        pass
    return report


@app.get("/api/investigations/{run_id}/live")
def live(run_id: str):
    """Read-only snapshot of a run for the live investigation timeline (works while running and after)."""
    state = _run(run_id)
    events = [{**e, "event_at": str(e["event_at"]),
               "details": json.loads(e["details"]) if isinstance(e["details"], str) and e["details"].startswith("{") else e["details"]}
              for e in state.get("events", [])]
    gw = state.get("guild_watcher") or {}
    gout = gw.get("output") or {}
    out = {
        "status": state.get("status"), "error": state.get("error"), "fallback_run_id": config.FALLBACK_RUN_ID or None,
        "run": {k: state.get(k) for k in ("run_id", "repo", "branch", "commit_sha", "started_at", "finished_at", "duration_ms")},
        "events": events,
        "guild": {"status": gw.get("status"), "session_url": gw.get("session_url"), "elapsed_s": gw.get("elapsed_s"),
                  "agent_runtime_s": gw.get("agent_runtime_s"), "error": gw.get("error"),
                  "tool_calls": [c if isinstance(c, dict) else {"call": c} for c in gw.get("tool_calls") or []],
                  "commit_sha": gout.get("commit_sha"), "package_count": gout.get("package_count"), "manifests": gout.get("manifests"),
                  "sources": [{k: s.get(k) for k in ("provider", "url", "status", "sha256", "bytes")} for s in gout.get("sources", [])],
                  "affected_packages": [f"{p['name']}@{p['version']}" for p in gout.get("affected_packages", [])]},
        "reports": state.get("github_reports"), "reports_error": state.get("github_reports_error"),
    }
    if state.get("status") != "complete":
        return out
    ov = overview(run_id)
    out["overview"] = {k: ov[k] for k in ("headline", "security", "evidence")}
    groups = state.get("groups", {})
    key = next((k for k, g in groups.items() if g["kind"] == "breaking_api"), None)
    if key:
        g = groups[key]
        sem = (state.get("semantic") or {}).get(g["change"]["change_id"]) or {}
        out["stripe"] = {
            "group_key": key, "change": {k: g["change"].get(k) for k in ("title", "api_version", "removed_symbols", "added_symbols", "source_url",
                                                                         "content_sha256", "guild_sha256", "guild_hash_agrees", "source_mode")},
            "hard_filter": g.get("hard_filter"), "semantic": {k: sem.get(k) for k in ("filtered_rows", "unfiltered_rows", "stats", "unfiltered_stats", "sql")},
        }
    sel = {k for k, g in groups.items() if any(f["group_key"] == k and f["confidence_tier"] in ("confirmed", "candidate", "upgrade_risk")
                                              for f in state["findings"])}
    out["findings"] = [{"finding_id": f["finding_id"], "group_key": f["group_key"], "path": f["path"], "line": f["line"], "tier": f["confidence_tier"],
                        "status": f["status"], "model_score": f.get("model_score"), "rule_id": (f.get("semgrep") or {}).get("rule_id"),
                        "matched": (f.get("semgrep") or {}).get("matched_code", "").strip()[:160],
                        "gate": {k: (f.get("version_gate") or {}).get(k) for k in ("rule", "basis", "affected", "api_version")}}
                       for f in state["findings"] if f["group_key"] in sel and f["status"] != "exposed"]
    hits = [(f["path"], f["line"]) for f in out["findings"]]
    seen, safe = set(), []
    for g in groups.values():
        for u in g.get("non_matching_uses", []):
            k = (u["path"], u["start_line"])
            if k in seen or any(p == u["path"] and u["start_line"] <= ln < u["start_line"] + 10 for p, ln in hits):
                continue
            seen.add(k)
            safe.append({"path": u["path"], "line": u["start_line"], "symbol": u["symbol"], "why": u["verdict"]})
    out["safe_exclusions"] = safe
    out["ml_calls"] = [{k: c.get(k) for k in ("endpoint", "roundtrip_ms", "server_ms", "n")} for c in (state.get("ml") or {}).get("calls", [])]
    return out
