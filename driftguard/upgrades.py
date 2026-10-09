"""Pick an upgrade target using registry versions + OSV, and disclose advisories that remain (edge case 11)."""
import json
import re
import xml.etree.ElementTree as ET

from . import sources, versions
from .security import safe_request

PRERELEASE = re.compile(r"(alpha|beta|rc|cr|milestone|snapshot|dev|pre|-)", re.I)


def registry_versions(ecosystem: str, name: str) -> list[str]:
    if ecosystem == "npm":
        data = safe_request("GET", f"https://registry.npmjs.org/{name}").json()
        vs = [v for v, meta in data["versions"].items() if not meta.get("deprecated")]
    elif ecosystem == "PyPI":
        data = safe_request("GET", f"https://pypi.org/pypi/{name}/json").json()
        vs = [v for v, files in data["releases"].items() if files and not any(f.get("yanked") for f in files)]
    elif ecosystem == "Maven":
        g, a = name.split(":")
        xml = safe_request("GET", f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/maven-metadata.xml").text
        vs = [v.text for v in ET.fromstring(xml).iter("version")]
    else:
        return []
    return [v for v in vs if not PRERELEASE.search(v.split("+")[0][1:] if ecosystem == "npm" else v)]


def select_upgrade(ecosystem: str, name: str, current: str, target_vuln: dict) -> dict:
    newer = versions.sort_versions(ecosystem, [v for v in registry_versions(ecosystem, name)
                                               if versions.compare(ecosystem, v, current) > 0])
    ids, fetched = sources.osv_querybatch([{"ecosystem": ecosystem, "name": name, "version": v} for v in newer])
    remaining = dict(zip(newer, ids))
    fixes_target = [v for v in newer if not versions.osv_affects(target_vuln, ecosystem, name, v)[0]]
    same_major = [v for v in fixes_target if v.split(".")[0] == current.split(".")[0]]
    clean_same = [v for v in same_major if not remaining[v]]
    clean_any = [v for v in fixes_target if not remaining[v]]
    pool = same_major or fixes_target
    chosen = (clean_same or clean_any or sorted(pool, key=lambda v: len(remaining[v])) or [None])[0]
    # Ordered attempts for the remediation engine: policy choice, newest clean in the same major, newest clean overall.
    attempts = []
    for v in [chosen, *(clean_same[-1:]), *(clean_any[-1:])]:
        if v and v not in attempts:
            attempts.append(v)
    minimal_fix = fixes_target[0] if fixes_target else None
    return {
        "ecosystem": ecosystem, "package": name, "current": current, "chosen": chosen, "attempt_order": attempts,
        "remaining_advisories": {v: remaining[v] for v in attempts},
        "chosen_remaining_advisories": remaining.get(chosen, []) if chosen else None,
        "minimal_fix_for_target": minimal_fix,
        "minimal_fix_remaining_advisories": remaining.get(minimal_fix, []) if minimal_fix else None,
        "candidates_checked": len(newer), "policy": "smallest same-major version that fixes the target advisory and has no "
        "known OSV advisories; then newest clean same-major; then newest clean overall", "osv_mode": fetched["source_mode"],
    }
