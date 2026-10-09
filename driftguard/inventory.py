"""Repository inventory at a pinned commit: resolved package versions and provider API-version settings.

Resolved versions come from lockfiles or exact pins only. A loose range (e.g. `Jinja2>=2.10`) is recorded as
version_unverified instead of being guessed.
"""
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .security import safe_request

SKIP_DIRS = {"node_modules", ".git", "target", "__pycache__", ".venv", ".pytest_cache"}


def walk(root: Path, patterns: tuple[str, ...]):
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file() and any(path.match(p) for p in patterns):
            yield path


def _purl(eco, name, version):
    kind = {"npm": "npm", "PyPI": "pypi", "Maven": "maven"}[eco]
    if eco == "Maven" and ":" in name:
        g, a = name.split(":", 1)
        return f"pkg:maven/{g}/{a}@{version}" if version else f"pkg:maven/{g}/{a}"
    return f"pkg:{kind}/{name}@{version}" if version else f"pkg:{kind}/{name}"


def npm_packages(root: Path):
    out = []
    for lock in walk(root, ("package-lock.json",)):
        data = json.loads(lock.read_text())
        rootpkg = data.get("packages", {}).get("", {})
        direct = set(rootpkg.get("dependencies", {})) | set(rootpkg.get("devDependencies", {}))
        for key, meta in data.get("packages", {}).items():
            if not key.startswith("node_modules/"):
                continue
            name = key.split("node_modules/")[-1]
            out.append({
                "ecosystem": "npm", "name": name, "version": meta.get("version"), "manifest": str(lock.relative_to(root)),
                "app_dir": str(lock.parent.relative_to(root)), "scope": "dev" if meta.get("dev") else "runtime",
                "relationship": "direct" if name in direct and key.count("node_modules/") == 1 else "transitive",
                "version_source": "lockfile", "version_verified": True,
            })
    return out


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([^\s;#]+)?")


def python_packages(root: Path):
    out = []
    for req in walk(root, ("requirements*.txt",)):
        for line in req.read_text().splitlines():
            if not line.strip() or line.strip().startswith(("#", "-")):
                continue
            m = REQ_LINE.match(line)
            if not m:
                continue
            name, op, ver = m.groups()
            name = re.sub(r"\[.*\]", "", name).lower()
            pinned = op == "==" and ver and "*" not in ver
            out.append({
                "ecosystem": "PyPI", "name": name, "version": ver if pinned else None, "constraint": f"{op or ''}{ver or ''}",
                "manifest": str(req.relative_to(root)), "app_dir": str(req.parent.relative_to(root)),
                "scope": "dev" if "dev" in req.name else "runtime", "relationship": "direct",
                "version_source": "exact_pin" if pinned else "unresolved_range", "version_verified": bool(pinned),
            })
    return out


def maven_packages(root: Path):
    out = []
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    for pom in walk(root, ("pom.xml",)):
        tree = ET.parse(pom).getroot()
        props = {child.tag.split("}")[1]: (child.text or "").strip() for child in tree.find("m:properties", ns) or []}
        text = pom.read_text().splitlines()
        for dep in tree.findall(".//m:dependencies/m:dependency", ns):
            g, a = dep.findtext("m:groupId", "", ns), dep.findtext("m:artifactId", "", ns)
            raw = dep.findtext("m:version", "", ns)
            ver = re.sub(r"\$\{([^}]+)\}", lambda mm: props.get(mm.group(1), mm.group(0)), raw)
            line = next((i + 1 for i, l in enumerate(text) if f"<artifactId>{a}</artifactId>" in l), 0)
            out.append({
                "ecosystem": "Maven", "name": f"{g}:{a}", "version": ver if ver and "${" not in ver else None,
                "manifest": str(pom.relative_to(root)), "manifest_line": line, "app_dir": str(pom.parent.relative_to(root)),
                "scope": "dev" if dep.findtext("m:scope", "", ns) == "test" else "runtime", "relationship": "direct",
                "version_source": "pom_declared", "version_verified": bool(ver and "${" not in ver),
            })
    return out


def stripe_sdk_default_api_version(sdk_version: str) -> dict:
    """Read the API version pinned by a stripe-node release straight from the published package."""
    url = f"https://unpkg.com/stripe@{sdk_version}/cjs/apiVersion.js"
    try:
        text = safe_request("GET", url).text
        m = re.search(r"ApiVersion\s*=\s*['\"]([^'\"]+)['\"]", text)
        return {"api_version": m.group(1) if m else None, "source": url}
    except Exception as exc:  # noqa: BLE001
        return {"api_version": None, "source": url, "error": str(exc)}


API_VERSION_RE = re.compile(r"""(?:apiVersion\s*:\s*|API_VERSION\s*=\s*)['"](\d{4}-\d{2}-\d{2}\.[a-z]+)['"]""")


def stripe_settings(root: Path, npm: list[dict]) -> dict:
    """Map each Stripe-using app (and each webhook handler) to the API version it actually receives."""
    apps = {}
    for pkg in npm:
        if pkg["name"] == "stripe" and pkg["relationship"] == "direct":
            sdk = stripe_sdk_default_api_version(pkg["version"])
            apps[pkg["app_dir"]] = {"sdk_version": pkg["version"], "sdk_default_api_version": sdk["api_version"],
                                    "sdk_version_source": sdk["source"], "explicit_api_version": None,
                                    "explicit_source": None, "webhook_endpoints": []}
    for app_dir, info in apps.items():
        for src in walk(root / app_dir, ("*.ts", "*.js")):
            m = API_VERSION_RE.search(src.read_text())
            if m:
                line = src.read_text()[: m.start()].count("\n") + 1
                info["explicit_api_version"] = m.group(1)
                info["explicit_source"] = f"{src.relative_to(root)}:{line}"
        for cfg in walk(root / app_dir, ("*webhook-endpoints*.json",)):
            for ep in json.loads(cfg.read_text()).get("endpoints", []):
                info["webhook_endpoints"].append({**ep, "config": str(cfg.relative_to(root))})
        info["effective_api_version"] = info["explicit_api_version"] or info["sdk_default_api_version"]
    return apps


def stripe_version_for_file(settings: dict, rel_path: str) -> dict:
    """Webhook handlers receive payloads in their endpoint's pinned version; other code uses the client version."""
    for app_dir, info in settings.items():
        if not rel_path.startswith(app_dir + "/"):
            continue
        local = rel_path[len(app_dir) + 1:]
        for ep in info["webhook_endpoints"]:
            if local in ep.get("handlers", []):
                return {"api_version": ep["api_version"], "basis": f"webhook endpoint {ep['url']} pinned in {ep['config']}"}
        basis = (f"explicit apiVersion at {info['explicit_source']}" if info["explicit_api_version"]
                 else f"stripe-node {info['sdk_version']} default ({info['sdk_version_source']})")
        return {"api_version": info["effective_api_version"], "basis": basis}
    return {"api_version": None, "basis": "no Stripe client configuration found for this path"}


def build(root: Path) -> dict:
    npm, py, mvn = npm_packages(root), python_packages(root), maven_packages(root)
    packages = npm + py + mvn
    for p in packages:
        p["purl"] = _purl(p["ecosystem"], p["name"], p["version"])
    languages = sorted({{".ts": "TypeScript", ".js": "JavaScript", ".py": "Python", ".java": "Java"}[f.suffix]
                        for f in walk(root, ("*.ts", "*.js", "*.py", "*.java"))})
    return {"packages": packages, "stripe": stripe_settings(root, npm), "languages": languages,
            "resolved": [p for p in packages if p["version_verified"]],
            "unverified": [p for p in packages if not p["version_verified"]]}
