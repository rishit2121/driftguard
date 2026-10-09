"""Evidence combiner: turns changes x inventory x Semgrep x vectors x ranker into normalized findings.

Authority order (never inverted):
  official advisory / changelog + deterministic version gate  >  Semgrep code evidence  >  regression test result
  semantic similarity and the ML rank only NOMINATE candidates or order them; they never override a version
  gate or a test outcome.

Confidence tiers
  confirmed           version affected + exact code match + regression test reproduced the failure
  likely              version affected + exact code match, no behavioral proof yet
  candidate           version affected + candidate use site; exploitability/reachability NOT proven
  upgrade_risk        code matches, but the API version this code receives is not yet affected
  inventory_only      affected version installed, no matching code use (or dev-only dependency)
  version_unverified  no resolved version (no lockfile / loose range) - not guessed
  review              semantic-only signal or insecure pattern without an advisory; human follow-up
"""
import hashlib
import json
import re

from . import inventory as inv_mod
from . import versions

TAB_FOR_STATUS = {
    "impacted": "advisories", "potentially_affected": "advisories", "exposed": "advisories",
    "upgrade_risk": "breaking", "needs_review": "review", "unverified": "review", "not_impacted": "ignored",
}


def finding_id(*parts) -> str:
    return "f_" + hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:14]


def _line_of(root, rel, needle) -> int:
    try:
        for i, line in enumerate((root / rel).read_text().splitlines(), 1):
            if needle in line:
                return i
    except OSError:
        pass
    return 1


def _line_of_ci(root, rel, needle) -> int:
    for i, line in enumerate((root / rel).read_text().splitlines(), 1):
        if needle.lower() in line.lower() and not line.lstrip().startswith("#"):
            return i
    return 1


def _snippet(root, rel, start, end, pad=6) -> dict:
    lines = (root / rel).read_text().splitlines()
    s, e = max(1, start - pad), min(len(lines), end + pad)
    return {"path": rel, "first_line": s, "lines": lines[s - 1 : e], "highlight": [start, end]}


def _overlaps_block(f, rows):
    for r in rows:
        if r["path"] == f["path"] and r["start_line"] <= f["line"] <= r["end_line"]:
            return r
    return None


# ----------------------------------------------------------------------------- Stripe / API contract drift

def _period_symbol(code: str) -> str:
    m = re.search(r"current_period_(start|end)", code)
    return f"subscription.{m.group(0)}" if m else ""


def api_change_group(change, ctx) -> dict:
    root, repo, sha = ctx["root"], ctx["repo"], ctx["sha"]
    stripe_apps = ctx["inventory"]["stripe"]
    group = {"key": change["change_id"], "kind": "breaking_api", "change": change, "findings": [], "semantic_only": [],
             "non_matching_uses": [], "hard_filter": {}}
    if change["provider"] != "stripe" or not stripe_apps:
        group["hard_filter"] = {"passed": False, "reason": f"repository has no {change['provider']} client/package"}
        return group
    group["hard_filter"] = {"passed": True, "reason": "stripe package resolved in lockfile: " +
                            ", ".join(f"{a} (stripe-node {i['sdk_version']})" for a, i in stripe_apps.items())}
    removed = {s.split(".")[-1] for s in change.get("removed_symbols", [])}
    semantic = ctx["semantic"].get(change["change_id"], {})
    sem_rows = semantic.get("filtered_rows", [])
    for m in ctx["semgrep"]:
        meta = m["metadata"]
        if meta.get("provider") != "stripe" or not removed & {s.split(".")[-1] for s in meta.get("symbols", [])}:
            continue
        gate = inv_mod.stripe_version_for_file(stripe_apps, m["path"])
        affected = bool(gate["api_version"]) and versions.stripe_version_at_least(gate["api_version"], change["min_affected_api_version"])
        f = {
            "finding_id": finding_id(repo, change["change_id"], m["path"], m["start_line"], m["rule_id"]),
            "group_key": group["key"], "finding_type": "breaking_api", "path": m["path"], "line": m["start_line"],
            "end_line": m["end_line"], "symbol": _period_symbol(m["matched_code"]), "semgrep": m,
            "status": "impacted" if affected else "upgrade_risk", "confidence_tier": "likely" if affected else "upgrade_risk",
            "version_gate": {**gate, "threshold": change["min_affected_api_version"], "affected": affected,
                             "rule": f"{gate['api_version']} >= {change['min_affected_api_version']}"},
            "reasons": [
                f"Official Stripe changelog removes {', '.join(change['removed_symbols'])} in {change['api_version']}",
                f"Semgrep {m['rule_id']} matched `{m['matched_code'].strip()[:90]}` (typed: Stripe.Subscription)",
                f"Code receives API version {gate['api_version']} ({gate['basis']})",
            ],
            "limitations": [] if affected else [
                f"This path is pinned to {gate['api_version']}; it breaks only when its endpoint is upgraded to "
                f"{change['min_affected_api_version']} or later. Future upgrade risk, not a current failure."],
            "code": _snippet(root, m["path"], m["start_line"], m["end_line"]),
        }
        block = _overlaps_block(f, sem_rows)
        if block:
            f["semantic"] = {"distance": block["distance"], "symbol": block["symbol"], "rank_in_candidates": block["rank"]}
        group["findings"].append(f)
    matched_blocks = {(f["path"], f["semantic"]["symbol"]) for f in group["findings"] if f.get("semantic")}
    for r in sem_rows:
        if (r["path"], r["symbol"]) not in matched_blocks:
            group["semantic_only"].append({**{k: r[k] for k in ("path", "start_line", "end_line", "symbol", "distance", "rank")},
                                           "verdict": "no exact Semgrep match; candidate not promoted"})
    group["unfiltered_baseline"] = semantic.get("unfiltered_rows", [])
    return group


# ----------------------------------------------------------------------------- OSV vulnerabilities

def _cve_key(change):
    return change.get("cve") or change["change_id"]


def vulnerability_groups(changes, ctx) -> list[dict]:
    root, repo = ctx["root"], ctx["repo"]
    pkgs = {(p["ecosystem"], p["name"].lower(), p["version"]): p for p in ctx["inventory"]["resolved"]}
    by_key: dict[tuple, list] = {}
    for c in changes:
        by_key.setdefault((c["ecosystem"], c["package"].lower(), _cve_key(c)), []).append(c)
    groups = []
    for (eco, name, cve), members in sorted(by_key.items()):
        primary = next((c for c in members if c["change_id"].startswith("GHSA")), members[0])
        pkg_list = [p for (e, n, v), p in pkgs.items() if e == eco and n == name]
        for pkg in pkg_list:
            affected, why = False, "no OSV record with ecosystem ranges"
            for c in members:
                affected, why = versions.osv_affects(c["osv"], eco, pkg["name"], pkg["version"])
                if affected:
                    break
            ids = sorted({c["change_id"] for c in members} | {a for c in members for a in c.get("aliases", [])})
            group = {"key": f"{pkg['name']}@{pkg['version']}:{cve}:{pkg['manifest']}", "kind": "vulnerability", "change": primary,
                     "osv_ids": ids, "package": pkg, "findings": [], "non_matching_uses": [],
                     "version_check": {"affected": affected, "reason": why, "installed": pkg["version"],
                                       "fixed_versions": versions.osv_fixed_versions(primary["osv"], eco, pkg["name"])}}
            base_reasons = [f"OSV {primary['change_id']} ({cve}) affects {pkg['name']} {pkg['version']}: {why}",
                            f"Version resolved from {pkg['manifest']} ({pkg['version_source']}, {pkg['scope']}, {pkg['relationship']})"]
            matches = [m for m in ctx["semgrep"]
                       if m["metadata"].get("package", "").lower() == pkg["name"].lower()
                       and m["path"].startswith(pkg["app_dir"] + "/")
                       and m["metadata"].get("change_id") in ids]
            if not affected:
                groups.append(group)
                continue
            if pkg["scope"] == "dev":
                group["findings"].append(_inventory_finding(group, root, repo, "dev dependency only: not shipped in the runtime "
                                                           "artifact; inventory exposure, not runtime reachability", base_reasons))
            elif matches:
                cap = matches[0]["metadata"].get("confidence_cap")
                for m in matches:
                    group["findings"].append({
                        "finding_id": finding_id(repo, cve, m["path"], m["start_line"], m["rule_id"]),
                        "group_key": group["key"], "finding_type": "vulnerable_dependency", "path": m["path"],
                        "line": m["start_line"], "end_line": m["end_line"], "symbol": m["matched_code"].strip()[:80],
                        "semgrep": m, "status": "potentially_affected" if cap == "candidate" else "impacted",
                        "confidence_tier": cap or "likely",
                        "reasons": base_reasons + [f"Semgrep {m['rule_id']} matched `{m['matched_code'].strip()[:90]}`"],
                        "limitations": ["A matched call site with an affected version is evidence of a potentially affected "
                                        "use, not proof of exploitability."] + (
                            ["Candidate only: exploitation additionally depends on runtime configuration (e.g. lookups enabled, "
                             "JDK, network egress). No exploit was executed."] if cap == "candidate" else []),
                        "version_gate": {"affected": True, "rule": why, "installed": pkg["version"]},
                        "code": _snippet(root, m["path"], m["start_line"], m["end_line"]),
                    })
            else:
                group["findings"].append(_inventory_finding(group, root, repo, "no matching code use found by the "
                                                           "package's Semgrep rules", base_reasons))
            # Show uses of the same package that did NOT match (e.g. yaml.safe_load) - evidence of correct non-alerts.
            for b in ctx["blocks"]:
                if b["package"].lower() == pkg["name"].lower() and b["path"].startswith(pkg["app_dir"] + "/") and not any(
                        m["path"] == b["path"] and b["start_line"] <= m["start_line"] <= b["end_line"] for m in matches):
                    group["non_matching_uses"].append({"path": b["path"], "start_line": b["start_line"], "symbol": b["symbol"],
                                                       "verdict": "uses the package but not the affected API"})
            groups.append(group)
    return groups


def _inventory_finding(group, root, repo, why, base_reasons):
    pkg = group["package"]
    needle = f"node_modules/{pkg['name']}\"" if pkg["ecosystem"] == "npm" else pkg["name"].split(":")[-1]
    line = pkg.get("manifest_line") or _line_of(root, pkg["manifest"], needle)
    return {"finding_id": finding_id(repo, group["key"], pkg["manifest"]), "group_key": group["key"],
            "finding_type": "inventory_exposure", "path": pkg["manifest"], "line": line, "end_line": line, "symbol": pkg["name"],
            "status": "exposed", "confidence_tier": "inventory_only", "reasons": base_reasons + [why],
            "limitations": ["Installed affected version without a matched use site. Not evidence of reachability."],
            "version_gate": {"affected": True, "rule": group["version_check"]["reason"], "installed": pkg["version"]},
            "code": _snippet(root, pkg["manifest"], line, line, pad=3)}


def unverified_findings(ctx, osv_counts) -> list[dict]:
    out = []
    for p in ctx["inventory"]["unverified"]:
        line = _line_of_ci(ctx["root"], p["manifest"], p["name"].split(":")[-1])
        n = osv_counts.get((p["ecosystem"], p["name"]), 0)
        out.append({"finding_id": finding_id(ctx["repo"], "unverified", p["manifest"], p["name"]), "group_key": f"unverified:{p['name']}",
                    "finding_type": "version_unverified", "path": p["manifest"], "line": line, "end_line": line, "symbol": p["name"],
                    "status": "unverified", "confidence_tier": "version_unverified",
                    "reasons": [f"{p['name']} is declared as `{p.get('constraint')}` with no lockfile: installed version unknown",
                                f"OSV lists {n} advisories for some versions of {p['name']}"],
                    "limitations": ["Version not guessed from a range. Add a lockfile / exact pin to evaluate advisories."],
                    "version_gate": {"affected": None, "rule": "version unverified"},
                    "code": _snippet(ctx["root"], p["manifest"], line, line, pad=3)})
    return out


def insecure_code_findings(ctx) -> list[dict]:
    out = []
    for m in ctx["semgrep"]:
        if m["metadata"].get("finding_kind") != "insecure_code":
            continue
        out.append({"finding_id": finding_id(ctx["repo"], m["rule_id"], m["path"], m["start_line"]), "group_key": m["rule_id"],
                    "finding_type": "insecure_code", "path": m["path"], "line": m["start_line"], "end_line": m["end_line"],
                    "symbol": m["metavars"].get("$F", ""), "semgrep": m, "status": "needs_review", "confidence_tier": "review",
                    "reasons": [m["message"], f"Semgrep {m['rule_id']}"], "source_url": (m["metadata"].get("references") or [""])[0],
                    "limitations": ["Pattern match on code that is not wired to a route in this repo; review before fixing."],
                    "code": _snippet(ctx["root"], m["path"], m["start_line"], m["end_line"])})
    return out


def rank_features(f) -> dict:
    gate = f.get("version_gate", {})
    return {"provider_match": 1, "symbol_match": 1 if f.get("semgrep") else 0,
            "version_applicable": 1 if gate.get("affected") else 0, "semgrep_match": 1 if f.get("semgrep") else 0,
            "test_failure": 1 if f.get("test_status") == "reproduced" else 0}


def ranker_inputs(f, change) -> dict:
    ctx_text = "\n".join(f["code"]["lines"]) if f.get("code") else f.get("symbol", "")
    change_text = f"{change.get('provider')} {change.get('package')}: {change.get('title')}\n{change.get('summary', '')[:800]}"
    return {"change_text": change_text, "code_context": f"// {f['path']}\n{ctx_text}"[:3000], "explicit_features": rank_features(f)}


def summarize(findings) -> dict:
    out = {}
    for f in findings:
        out.setdefault(f["status"], 0)
        out[f["status"]] += 1
    return out


def dumps(obj) -> str:
    return json.dumps(obj, default=str)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]
