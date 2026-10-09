"""Deterministic, ecosystem-aware version comparison and OSV range evaluation (no string comparisons)."""
import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version


def _semver_key(v: str):
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?", v.strip())
    if not m:
        raise ValueError(f"not semver: {v}")
    major, minor, patch, pre = m.groups()
    nums = (int(major), int(minor or 0), int(patch or 0))
    if pre is None:
        return nums + ((1,),)
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return nums + ((0,) + parts,)


_MAVEN_QUALIFIERS = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4, "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7}


def _maven_key(v: str):
    tokens = re.findall(r"\d+|[A-Za-z]+", v.lower())
    key = []
    for t in tokens:
        if t.isdigit():
            key.append((1, int(t)))
        else:
            key.append((0, _MAVEN_QUALIFIERS.get(t, 0)))
    return key


def _maven_cmp(a: str, b: str) -> int:
    ka, kb = _maven_key(a), _maven_key(b)
    for i in range(max(len(ka), len(kb))):
        # A missing token equals 0 against a number and "release" against a qualifier (2.0 == 2.0.0 > 2.0-beta9).
        x = ka[i] if i < len(ka) else ((1, 0) if kb[i][0] == 1 else (0, 6))
        y = kb[i] if i < len(kb) else ((1, 0) if ka[i][0] == 1 else (0, 6))
        if x != y:
            return -1 if x < y else 1
    return 0


def compare(ecosystem: str, a: str, b: str) -> int:
    eco = (ecosystem or "").lower()
    if eco == "pypi":
        try:
            va, vb = Version(a), Version(b)
            return (va > vb) - (va < vb)
        except InvalidVersion:
            pass
    if eco == "maven":
        return _maven_cmp(a, b)
    ka, kb = _semver_key(a), _semver_key(b)
    return (ka > kb) - (ka < kb)


def sort_versions(ecosystem: str, versions):
    return sorted(versions, key=cmp_to_key(lambda a, b: compare(ecosystem, a, b)))


def osv_affects(vuln: dict, ecosystem: str, package: str, version: str) -> tuple[bool, str]:
    """Evaluate OSV `affected` ranges locally. Returns (affected, human-readable reason)."""
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").lower() != ecosystem.lower() or pkg.get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced, active = None, False
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                    active = introduced == "0" or compare(ecosystem, version, introduced) >= 0
                elif "fixed" in ev and active:
                    if compare(ecosystem, version, ev["fixed"]) < 0:
                        return True, f"introduced {introduced} <= {version} < fixed {ev['fixed']}"
                    active = False
                elif "last_affected" in ev and active:
                    if compare(ecosystem, version, ev["last_affected"]) <= 0:
                        return True, f"introduced {introduced} <= {version} <= last_affected {ev['last_affected']}"
                    active = False
            if active:
                return True, f"introduced {introduced} <= {version} (no fix event)"
        if version in aff.get("versions", []):
            return True, f"{version} listed in OSV affected versions"
    return False, "version outside all affected ranges"


def osv_fixed_versions(vuln: dict, ecosystem: str, package: str) -> list[str]:
    out = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").lower() == ecosystem.lower() and pkg.get("name", "").lower() == package.lower():
            for rng in aff.get("ranges", []):
                out += [ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev]
    return sort_versions(ecosystem, set(out))


def stripe_api_version_key(v: str) -> str:
    """'2025-03-31.basil' -> '2025-03-31' (Stripe API versions are ordered by release date)."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", v or "")
    if not m:
        raise ValueError(f"not a Stripe API version: {v}")
    return m.group(1)


def stripe_version_at_least(v: str, threshold: str) -> bool:
    return stripe_api_version_key(v) >= stripe_api_version_key(threshold)  # ISO dates compare chronologically
