"""End-to-end investigation: sources -> repo snapshot -> ClickHouse/Akash retrieval -> Semgrep -> evidence ->
regression proof -> (on request) remediation + draft PR."""
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import analysis, codeindex, config, github, github_reporting, guild_bridge, pr, remediation, semgrep_runner, sources, store
from . import inventory as inv_mod
from .ml import MLService
from .security import detect_instruction_like

RUNS: dict[str, dict] = {}
_GUILD_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="guild")
_ATTACH_LOCK = threading.Lock()


def _guild_watch(repo, branch, sha, run_id, log, state):
    """Runs concurrently with the investigation. Its evidence is attached to the run when Guild finishes, which can be
    after the platform's own analysis completes (Guild session latency varies widely)."""
    def created(session_id, url):
        state["guild_watcher"] = {"session_id": session_id, "session_url": url, "status": "RUNNING"}

    with log.stage("guild_watcher", "guild") as st:
        try:
            watch = guild_bridge.run_watcher(repo, branch, on_created=created)
        except Exception as exc:  # noqa: BLE001 - the platform's own watcher still runs
            st.result, st.details = "error", {"error": f"{type(exc).__name__}: {exc}"}
            state["guild_watcher"] = {**(state.get("guild_watcher") or {}), "status": "ERROR", "error": st.details["error"]}
            _attach_guild(state, None)
            return None
        out = watch["output"] or {}
        st.details = {"session_url": watch["session_url"], "status": watch["status"],
                      "guild_commit_sha": out.get("commit_sha"), "sha_agrees": out.get("commit_sha") == sha,
                      "manifests": out.get("manifests"), "package_count": out.get("package_count"),
                      "affected_packages": [f"{p['name']}@{p['version']}" for p in out.get("affected_packages", [])],
                      "elapsed_s": watch["elapsed_s"],
                      "tool_calls": [f"{c['call']} ({c['ms']} ms)" for c in watch.get("tool_calls", [])]}
        st.result = "ok" if out else "error"
        for src in out.get("sources", []):
            store.insert("source_observations", [{
                "observed_at": store.now(), "provider": src["provider"], "source_url": src["url"],
                "source_kind": "guild_watcher", "content_sha256": src["sha256"], "change_id": "",
                "text": f"fetched by Guild session {watch['session_id']} ({src['bytes']} bytes)",
                "http_status": src["status"], "run_id": run_id}])
    state["guild_watcher"] = {k: v for k, v in watch.items() if k != "trace"}
    _attach_guild(state, watch)
    return watch


def _attach_guild(state, watch):
    """Cross-check Guild's independent fetch against the platform's; re-persist if the run already completed."""
    with _ATTACH_LOCK:
        state["_guild_done"] = True
        if watch and watch.get("output") and state.get("_stripe_changes") is not None:
            guild_hashes = {x["url"]: x["sha256"] for x in watch["output"].get("sources", [])}
            for c in state["_stripe_changes"]:
                c["guild_sha256"] = guild_hashes.get(c["source_url"])
                c["guild_hash_agrees"] = c["guild_sha256"] == c["content_sha256"]
                for g in (state.get("groups") or {}).values():
                    if g["change"].get("change_id") == c["change_id"]:
                        g["change"]["guild_sha256"], g["change"]["guild_hash_agrees"] = c["guild_sha256"], c["guild_hash_agrees"]
        if state.get("status") == "complete":
            _persist_run(state)


_LOCK = threading.Lock()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def start(repo: str = config.DEMO_REPO, branch: str = config.DEMO_BRANCH, prove: bool = True) -> str:
    run_id = "run_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:6]
    RUNS[run_id] = {"run_id": run_id, "repo": repo, "branch": branch, "status": "running", "started_at": _now_iso(), "events": []}
    threading.Thread(target=_guarded, args=(run_id, repo, branch, prove), daemon=True).start()
    return run_id


def _guarded(run_id, repo, branch, prove):
    try:
        with _LOCK:
            investigate(repo, branch, run_id, prove)
    except Exception as exc:  # noqa: BLE001
        RUNS[run_id].update(status="error", error=f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc())
        _persist_run(RUNS[run_id])


def investigate(repo: str, branch: str, run_id: str | None = None, prove: bool = True) -> dict:
    run_id = run_id or "run_" + uuid.uuid4().hex[:10]
    state = RUNS.setdefault(run_id, {"run_id": run_id, "repo": repo, "branch": branch, "status": "running", "started_at": _now_iso()})
    log = store.RunLog(run_id)
    state["events"] = log.events
    ml = MLService()
    t_start = time.perf_counter()

    # 1. Repository snapshot at an immutable SHA ---------------------------------------------------------
    with log.stage("repo_snapshot", "github") as st:
        info = github.repo_info(repo)
        sha = github.resolve_sha(repo, branch)
        root = github.checkout(repo, sha)
        st.details = {"repo": repo, "branch": branch, "commit_sha": sha, "url": info["html_url"]}
    state.update(commit_sha=sha, repo_info=info)

    with log.stage("inventory", "github") as st:
        inventory = inv_mod.build(root)
        st.details = {"packages": len(inventory["packages"]), "resolved": len(inventory["resolved"]),
                      "unverified": [p["name"] for p in inventory["unverified"]], "languages": inventory["languages"],
                      "stripe_api_versions": {a: i["effective_api_version"] for a, i in inventory["stripe"].items()}}
    state["inventory"] = {"languages": inventory["languages"], "package_count": len(inventory["packages"]),
                          "direct": [p for p in inventory["packages"] if p["relationship"] == "direct"],
                          "unverified": inventory["unverified"], "stripe": inventory["stripe"]}

    # 2. Source watchers -----------------------------------------------------------------------------
    # The Guild watcher session runs concurrently with the platform's own source fetches (independent evidence).
    if config.GUILD_WATCHER_AGENT:
        state["guild_watcher"] = {"status": "STARTING"}
        _GUILD_POOL.submit(_guild_watch, repo, branch, sha, run_id, log, state)
    stripe_changes = sources.watch_stripe(run_id, log)
    shopify_changes = sources.watch_shopify(run_id, log)
    osv_changes = sources.watch_osv(inventory["resolved"], run_id, log)
    with log.stage("source_fetch", "osv_unverified") as st:
        osv_counts = {}
        for p in inventory["unverified"]:
            resp = sources.safe_request("POST", f"{config.OSV_API}/query", json={"package": {"ecosystem": p["ecosystem"], "name": p["name"]}})
            osv_counts[(p["ecosystem"], p["name"])] = len(resp.json().get("vulns", []))
        st.details = {f"{k[0]}:{k[1]}": v for k, v in osv_counts.items()}
    state["sources"] = [{"provider": c["provider"], "url": c["source_url"], "sha256": c["content_sha256"],
                         "state": c["observation_state"], "mode": c.get("source_mode"), "fetched_at": c.get("fetched_at"),
                         "change_id": c["change_id"]} for c in stripe_changes + osv_changes] + [
        {"provider": "shopify", "url": config.SHOPIFY_FEED_URL, "entries": len(shopify_changes),
         "new_or_updated": sum(c["observation_state"] != "unchanged" for c in shopify_changes)}]

    # 3. Embeddings (Akash) + ClickHouse vector retrieval ----------------------------------------------
    semantic, ml_info = {}, {}
    try:
        with log.stage("ml_health", "akash") as st:
            ml_info["health"] = ml.health()
            st.details = ml_info["health"]
        codeindex.index_changes(stripe_changes + osv_changes + shopify_changes, ml, log)
        codeindex.index_repo(root, repo, sha, ml, log)
        targets = list(stripe_changes)
        seen = set()
        for c in osv_changes:
            if c["package"] not in seen:
                seen.add(c["package"])
                targets.append(c)
        for c in targets:
            with log.stage("vector_retrieval", "clickhouse") as st:
                res = codeindex.retrieve(c, repo, sha, ml, run_id)
                rows = store.rows_as_dicts(res["filtered"])
                for i, r in enumerate(rows, 1):
                    r["rank"] = i
                    r.pop("usage_context", None)
                base = store.rows_as_dicts(res["unfiltered"])
                for i, r in enumerate(base, 1):
                    r["rank"] = i
                    r.pop("usage_context", None)
                semantic[c["change_id"]] = {"filtered_rows": rows, "unfiltered_rows": base, "sql": res["filtered"]["sql"],
                                            "stats": res["filtered"]["stats"], "unfiltered_stats": res["unfiltered"]["stats"]}
                st.details = {"change_id": c["change_id"], "package": c["package"], "candidates": len(rows),
                              "elapsed_ms": res["filtered"]["stats"]["elapsed_ms"], "rows_read": res["filtered"]["stats"]["rows_read"],
                              "top": [(r["path"], r["symbol"], round(r["distance"], 4)) for r in rows[:3]]}
        for c in osv_changes:
            semantic.setdefault(c["change_id"], semantic.get(next(t["change_id"] for t in targets if t.get("package") == c["package"]), {}))
    except Exception as exc:  # noqa: BLE001 - semantic evidence is optional, but its absence is reported
        ml_info["error"] = f"{type(exc).__name__}: {exc}"
        log.event("ml_unavailable", "akash", 0, "error", {"error": ml_info["error"]})

    # 4. Semgrep -------------------------------------------------------------------------------------------
    with log.stage("semgrep", "semgrep") as st:
        sg = semgrep_runner.scan(root)
        st.details = {"results": len(sg["results"]), "errors": sg["errors"], "elapsed_ms": round(sg["elapsed_ms"]), "version": sg["version"],
                      "matches": [f"{r['path']}:{r['start_line']} {r['rule_id']}" for r in sg["results"]]}
    rules = semgrep_runner.load_rules()

    # 5. Evidence combination --------------------------------------------------------------------------------
    ctx = {"root": root, "repo": repo, "sha": sha, "inventory": inventory, "semgrep": sg["results"], "semantic": semantic,
           "blocks": codeindex.extract_blocks(root)}
    with log.stage("evidence_combine", "driftguard") as st:
        groups = [analysis.api_change_group(c, ctx) for c in stripe_changes]
        groups += analysis.vulnerability_groups(osv_changes, ctx)
        extra = analysis.unverified_findings(ctx, osv_counts) + analysis.insecure_code_findings(ctx)
        findings = [f for g in groups for f in g["findings"]] + extra
        st.details = {"groups": len(groups), "findings": len(findings), "by_status": analysis.summarize(findings)}

    # 6. Regression proof (pre/post fixtures, inert security probes) ----------------------------------------
    proofs = {}
    if prove:
        for g in groups:
            if any(f["status"] in ("impacted",) for f in g["findings"]) and remediation.playbook_for(g):
                proofs[g["key"]] = remediation.prove(g, repo, sha, log)
                if proofs[g["key"]]["status"] == "reproduced":
                    for f in g["findings"]:
                        if f["status"] == "impacted":
                            f["confidence_tier"] = "confirmed"
                            f["test_status"] = "reproduced"
                            f["reasons"].append("Regression test reproduced the failure on the unpatched code at this SHA")
    for f in findings:
        f.setdefault("test_status", "not_run")

    # 7. Akash ranker over code-level evidence -----------------------------------------------------------
    change_by_group = {g["key"]: g["change"] for g in groups}
    ranked = [f for f in findings if f.get("code") and f["group_key"] in change_by_group]
    if ranked and "error" not in ml_info:
        try:
            with log.stage("ml_rank", "akash") as st:
                resp = ml.rank([analysis.ranker_inputs(f, change_by_group[f["group_key"]]) for f in ranked])
                for f, s, cos in zip(ranked, resp["scores"], resp.get("cosine", [None] * len(ranked))):
                    f["model_score"], f["model_cosine"] = s, cos
                    f["model_version"] = resp["model_version"]
                st.details = {"pairs": len(ranked), "model_version": resp["model_version"], "server_ms": resp.get("elapsed_ms")}
            with log.stage("ml_classify", "akash") as st:
                n = 0
                for g in groups:
                    for cand in g.get("semantic_only", [])[:4]:
                        block = next((b for b in ctx["blocks"] if b["path"] == cand["path"] and b["start_line"] == cand["start_line"]), None)
                        if not block:
                            continue
                        cls = ml.classify(codeindex.change_text(g["change"]),
                                          block["usage_context"], {"provider_match": 1, "symbol_match": 0, "version_applicable": 0, "semgrep_match": 0, "test_failure": 0})
                        cand["classifier"] = {k: cls[k] for k in ("relevance_label", "score", "finding_kind")}
                        n += 1
                st.details = {"semantic_only_classified": n}
        except Exception as exc:  # noqa: BLE001
            ml_info["rank_error"] = f"{type(exc).__name__}: {exc}"
    ml_info["calls"] = ml.calls

    # 8. Untrusted-content quarantine (never promoted to instructions) ------------------------------------
    quarantine = [{"source": c["source_url"], "spans": c["quarantined_instructions"]} for c in stripe_changes if c["quarantined_instructions"]]
    for path in inv_mod.walk(root, ("*.md",)):
        hits = detect_instruction_like(path.read_text(errors="ignore"))
        if hits:
            quarantine.append({"source": str(path.relative_to(root)), "spans": hits[:3]})
    log.event("quarantine", "driftguard", 0, "ok", {"items": len(quarantine), "action": "stored as evidence only; no tool call derived"})

    # 9. Persist ------------------------------------------------------------------------------------------
    now = store.now()
    for f in findings:
        change = change_by_group.get(f["group_key"], {})
        f.update(repo=repo, commit_sha=sha, change_id=change.get("change_id", f["group_key"]),
                 source_url=f.get("source_url") or change.get("source_url", ""), run_id=run_id,
                 tab=analysis.TAB_FOR_STATUS.get(f["status"], "review"))
        if f["finding_type"] == "breaking_api" and f["status"] == "impacted":
            f["tab"] = "breaking"
    store.insert("findings", [{
        "observed_at": now, "finding_id": f["finding_id"], "repo": repo, "commit_sha": sha, "change_id": f["change_id"],
        "finding_type": f["finding_type"], "path": f["path"], "line": f["line"], "status": f["status"],
        "confidence_tier": f["confidence_tier"], "source_url": f["source_url"], "model_score": float(f.get("model_score") or 0),
        "semgrep_rule": (f.get("semgrep") or {}).get("rule_id", ""), "test_status": f["test_status"], "pr_url": ""} for f in findings])
    store.insert("finding_evidence", [{"observed_at": now, "finding_id": f["finding_id"], "run_id": run_id,
                                       "evidence": analysis.dumps(f)} for f in findings])

    changes_view = _changes_view(groups, shopify_changes, extra)
    state["_stripe_changes"] = stripe_changes
    state.update(
        status="complete", finished_at=_now_iso(), duration_ms=round((time.perf_counter() - t_start) * 1000),
        groups={g["key"]: _group_view(g, proofs.get(g["key"])) for g in groups},
        findings=findings, changes=changes_view, ml=ml_info, quarantine=quarantine,
        semgrep={"version": sg["version"], "elapsed_ms": round(sg["elapsed_ms"]), "results": len(sg["results"]),
                 "command": sg["command"], "rules": {k: {"file": v["file"], "message": v["message"].strip(), "yaml": v["yaml"]} for k, v in rules.items()}},
        semantic={k: v for k, v in semantic.items() if k in {g["change"]["change_id"] for g in groups}},
        counts=analysis.summarize(findings), proofs=proofs,
    )
    if state.get("_guild_done"):
        _attach_guild(state, state.get("guild_watcher") if (state.get("guild_watcher") or {}).get("output") else None)
    else:
        _persist_run(state)
    _report_async(state, log)
    return state


def _report_async(state, log, group_key=None):
    """Upsert GitHub Issues / inline PR comments for confirmed findings without delaying the run."""
    if not config.GITHUB_REPORTS:
        return

    def work():
        try:
            if group_key:
                sub = {**state, "groups": {group_key: state["groups"][group_key]}}
                reports = github_reporting.report_run(sub, log)
            else:
                reports = github_reporting.report_run(state, log)
            state.setdefault("github_reports", {}).update(reports)
        except Exception as exc:  # noqa: BLE001 - reporting must never break an investigation
            state["github_reports_error"] = f"{type(exc).__name__}: {exc}"
        with _ATTACH_LOCK:
            _persist_run(state)

    threading.Thread(target=work, daemon=True).start()


def _group_view(g, proof):
    out = {k: v for k, v in g.items() if k not in ("findings", "change")}
    out["change"] = {k: v for k, v in g["change"].items() if k not in ("osv", "source_text")}
    out["source_text"] = g["change"].get("source_text") or g["change"].get("summary")
    out["finding_ids"] = [f["finding_id"] for f in g["findings"]]
    out["proof"] = proof
    out["remediable"] = bool(proof and proof.get("status") == "reproduced")
    return out


def _changes_view(groups, shopify_changes, extra):
    rows = []
    for g in groups:
        st = analysis.summarize(g["findings"])
        c = g["change"]
        if g["kind"] == "breaking_api":
            tab = "breaking" if g["findings"] else "ignored"
        else:
            tab = "advisories" if g["findings"] else "ignored"
        rows.append({"group_key": g["key"], "kind": g["kind"], "provider": c["provider"], "change_id": c["change_id"],
                     "title": c.get("title"), "cve": c.get("cve"), "severity": c.get("severity"), "source_url": c["source_url"],
                     "published_at": c.get("published_at"), "package": (g.get("package") or {}).get("name") or c.get("package"),
                     "installed": (g.get("package") or {}).get("version"), "affected_versions": c.get("affected_api_versions"),
                     "files": len({f["path"] for f in g["findings"]}), "counts": st, "tab": tab,
                     "top_tier": _top_tier(g["findings"]), "observation_state": c.get("observation_state"),
                     "fetched_at": c.get("fetched_at"), "source_mode": c.get("source_mode")})
    for f in extra:
        rows.append({"group_key": f["group_key"], "kind": f["finding_type"], "provider": "semgrep" if f["finding_type"] == "insecure_code" else "osv",
                     "change_id": f["group_key"], "title": f["reasons"][0], "source_url": f.get("source_url", ""), "files": 1,
                     "counts": {f["status"]: 1}, "tab": "review", "top_tier": f["confidence_tier"], "package": f["symbol"]})
    for c in shopify_changes:
        rows.append({"group_key": c["change_id"], "kind": "api_change", "provider": "shopify", "change_id": c["change_id"],
                     "title": c["title"], "source_url": c["source_url"], "published_at": c["published_at"], "files": 0, "counts": {},
                     "tab": "ignored", "top_tier": None, "affected_versions": c["affected_api_versions"],
                     "ignored_reason": "hard filter: repository has no Shopify client/package", "observation_state": c["observation_state"]})
    return rows


TIER_ORDER = ["confirmed", "likely", "candidate", "upgrade_risk", "review", "version_unverified", "inventory_only"]


def _top_tier(findings):
    tiers = [f["confidence_tier"] for f in findings]
    return next((t for t in TIER_ORDER if t in tiers), None)


def _persist_run(state):
    slim = {k: v for k, v in state.items() if k not in ("events",) and not k.startswith("_")}
    store.insert("investigations", [{"started_at": store.now(), "run_id": state["run_id"], "repo": state["repo"],
                                     "branch": state["branch"], "commit_sha": state.get("commit_sha", ""),
                                     "status": state["status"], "summary": analysis.dumps(slim)}])


def load_run(run_id: str) -> dict | None:
    if run_id in RUNS:
        return RUNS[run_id]
    rows = store.client().query("SELECT summary FROM investigations FINAL WHERE run_id = {r:String}", parameters={"r": run_id}).result_rows
    if not rows:
        return None
    import json
    state = json.loads(rows[0][0])
    state["events"] = [dict(zip(["event_at", "stage", "provider", "duration_ms", "result", "details"], r)) for r in store.client().query(
        "SELECT event_at, stage, provider, duration_ms, result, details FROM run_events WHERE run_id={r:String} ORDER BY event_at",
        parameters={"r": run_id}).result_rows]
    RUNS[run_id] = state
    return state


def latest_run_id(repo: str = config.DEMO_REPO) -> str | None:
    rows = store.client().query("SELECT run_id FROM investigations FINAL WHERE repo={r:String} AND status='complete' "
                                "ORDER BY started_at DESC LIMIT 1", parameters={"r": repo}).result_rows
    return rows[0][0] if rows else None


# ----------------------------------------------------------------------------- remediation + PR

REMEDIATIONS: dict[str, dict] = {}


def start_remediation(run_id: str, group_key: str) -> str:
    rem_id = "rem_" + uuid.uuid4().hex[:8]
    REMEDIATIONS[rem_id] = {"rem_id": rem_id, "run_id": run_id, "group_key": group_key, "status": "running", "started_at": _now_iso()}
    threading.Thread(target=_remediate_guarded, args=(rem_id,), daemon=True).start()
    return rem_id


def _remediate_guarded(rem_id):
    rem = REMEDIATIONS[rem_id]
    try:
        with _LOCK:
            remediate(rem)
    except Exception as exc:  # noqa: BLE001
        rem.update(status="error", error=f"{type(exc).__name__}: {exc}", traceback=traceback.format_exc())


def _rebuild_group(state, group_key):
    gv = state["groups"][group_key]
    findings = [f for f in state["findings"] if f["group_key"] == group_key]
    group = {"key": group_key, "kind": gv["kind"], "findings": findings, "package": gv.get("package")}
    # Re-fetch the full change record (OSV object) - the slim view drops it.
    if gv["kind"] == "vulnerability":
        vuln = sources.osv_vuln(gv["change"]["change_id"])
        group["change"] = {**gv["change"], "osv": vuln}
    else:
        group["change"] = gv["change"]
    return group


def remediate(rem: dict) -> dict:
    state = load_run(rem["run_id"])
    repo, sha, branch = state["repo"], state["commit_sha"], state["branch"]
    log = store.RunLog(rem["run_id"])
    rem["events"] = log.events
    group = _rebuild_group(state, rem["group_key"])

    # Edge case 12: the branch may have moved since the scan. Re-scan before building the PR.
    with log.stage("pre_pr_rescan", "github") as st:
        head = github.resolve_sha(repo, branch)
        st.details = {"scanned_sha": sha, "branch_head": head, "moved": head != sha}
        if head != sha:
            root = github.checkout(repo, head)
            rescan = semgrep_runner.scan(root)["results"]
            moved = []
            for f in group["findings"]:
                if not f.get("semgrep"):
                    continue
                new = next((r for r in rescan if r["rule_id"] == f["semgrep"]["rule_id"] and r["path"] == f["path"]
                            and r["matched_code"] == f["semgrep"]["matched_code"]), None)
                if new is None:
                    raise RuntimeError(f"{f['path']}:{f['line']} no longer matches at {head[:8]}; re-run the investigation")
                if new["start_line"] != f["line"]:
                    moved.append(f"{f['path']}: line {f['line']} -> {new['start_line']}")
                f["semgrep"], f["line"] = new, new["start_line"]
            st.details["moved_lines"] = moved
            sha = head
    rem["base_sha"] = sha
    result = remediation.remediate(group, repo, sha, log)
    rem["result"] = result
    if result["status"] != "accepted":
        rem["status"] = "no_passing_candidate"
        return rem
    if rem.get("dry_run"):
        rem["status"] = "verified_dry_run"
        return rem
    proof = state["groups"][rem["group_key"]].get("proof")
    with log.stage("pull_request", "guild" if config.PR_EXECUTOR == "guild" else "github") as st:
        opened = pr.open_pull_request(state, group, result, proof, sha)
        st.details = {k: v for k, v in opened.items() if k != "body"}
    rem.update(status="pr_opened", pr=opened)
    now = store.now()
    store.insert("findings", [{
        "observed_at": now, "finding_id": f["finding_id"], "repo": repo, "commit_sha": state["commit_sha"], "change_id": f["change_id"],
        "finding_type": f["finding_type"], "path": f["path"], "line": f["line"], "status": f["status"],
        "confidence_tier": f["confidence_tier"], "source_url": f["source_url"], "model_score": float(f.get("model_score") or 0),
        "semgrep_rule": (f.get("semgrep") or {}).get("rule_id", ""), "test_status": "patch_verified", "pr_url": opened["url"]}
        for f in group["findings"] if f["status"] == "impacted"])
    for f in state["findings"]:
        if f["group_key"] == rem["group_key"] and f["status"] == "impacted":
            f["pr_url"], f["test_status"] = opened["url"], "patch_verified"
    state["groups"][rem["group_key"]]["remediation"] = {"rem_id": rem["rem_id"], "pr": opened, "attempts": [
        {k: v for k, v in a.items() if k != "diff"} for a in result["attempts"]], "accepted": result["accepted"]["candidate"],
        "diff": result["accepted"]["diff"], "upgrade_plan": result.get("upgrade_plan")}
    _persist_run(state)
    _report_async(state, log, rem["group_key"])
    return rem
