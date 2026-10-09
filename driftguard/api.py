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
    slim = {k: v for k, v in state.items() if k not in ("findings", "groups", "semantic", "proofs", "traceback")}
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
    return {"finding": f, "group": g, "rule": rule, "siblings": siblings, "repo": state["repo"], "commit_sha": state["commit_sha"],
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
