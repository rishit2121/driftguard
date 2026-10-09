"""Runs Semgrep on a read-only checkout and normalizes results (path, lines, rule, matched code)."""
import json
import subprocess
import time
from pathlib import Path

import yaml

from . import config


def load_rules() -> dict:
    rules = {}
    for f in sorted(config.RULES_DIR.glob("*.yaml")):
        for r in yaml.safe_load(f.read_text())["rules"]:
            rules[r["id"]] = {**r, "file": f.name, "yaml": f.read_text()}
    return rules


def scan(root: Path, paths: list[str] | None = None) -> dict:
    cmd = [config.SEMGREP_BIN, "scan", "--config", str(config.RULES_DIR), "--json", "--metrics=off", "--quiet",
           "--disable-version-check", "--exclude", "node_modules", "--exclude", "*.test.*", "--exclude", "tests"]
    cmd += paths or ["."]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=600)
    elapsed = (time.perf_counter() - t0) * 1000
    data = json.loads(proc.stdout or "{}")
    results = []
    for r in data.get("results", []):
        lines = (root / r["path"]).read_text().splitlines()
        s, e = r["start"]["line"], r["end"]["line"]
        results.append({
            "rule_id": _short(r["check_id"]),
            "path": r["path"], "start_line": s, "end_line": e, "start_col": r["start"]["col"], "end_col": r["end"]["col"],
            "start_offset": r["start"]["offset"], "end_offset": r["end"]["offset"],
            "matched_code": "\n".join(lines[s - 1 : e]),
            "metavars": {k: v.get("abstract_content") for k, v in r["extra"].get("metavars", {}).items()},
            "message": r["extra"].get("message", "").strip(), "severity": r["extra"].get("severity"),
            "metadata": r["extra"].get("metadata", {}),
        })
    return {"results": results, "errors": [e.get("message", "")[:300] for e in data.get("errors", [])],
            "elapsed_ms": elapsed, "version": data.get("version"), "command": " ".join(cmd[:1] + cmd[2:])}


def _short(check_id: str) -> str:
    """Semgrep prefixes rule ids with the config path; map back to the declared rule id."""
    for rule_id in load_rules():
        if check_id.endswith(rule_id):
            return rule_id
    return check_id
