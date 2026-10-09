"""Source watchers: official Stripe changelog, Shopify changelog feed, OSV advisories.

Every fetch is recorded in source_observations with URL, time, HTTP status and the SHA-256 of the
normalized content. Successful live fetches are snapshotted to data/snapshots; snapshots are only used as a
DISCLOSED fallback (source_mode = "cached_snapshot") when the live source is unavailable.
"""
import hashlib
import html
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from . import config, store
from .security import detect_instruction_like, safe_request


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _snapshot_path(url: str):
    return config.SNAPSHOT_DIR / (hashlib.sha1(url.encode()).hexdigest() + ".json")


def fetch_text(url: str, *, method="GET", json_body=None) -> dict:
    """Live fetch with disclosed snapshot fallback."""
    config.SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    fetched_at = datetime.now(timezone.utc)
    try:
        resp = safe_request(method, url, json=json_body)
        resp.raise_for_status()
        out = {"url": url, "status": resp.status_code, "text": resp.text, "fetched_at": fetched_at.isoformat(),
               "source_mode": "live"}
        _snapshot_path(url + (json.dumps(json_body, sort_keys=True) if json_body else "")).write_text(json.dumps(out))
        return out
    except Exception as exc:  # noqa: BLE001 - any failure -> disclosed fallback
        snap = _snapshot_path(url + (json.dumps(json_body, sort_keys=True) if json_body else ""))
        if snap.exists():
            out = json.loads(snap.read_text())
            out["source_mode"] = "cached_snapshot"
            out["live_error"] = f"{type(exc).__name__}: {exc}"
            return out
        raise


def observe(provider, url, kind, text, status, change_id, run_id, observed_at=None):
    digest = sha256(text)
    prev = store.client().query(
        "SELECT content_sha256 FROM source_observations WHERE source_url = {u:String} ORDER BY observed_at DESC LIMIT 1",
        parameters={"u": url},
    ).result_rows
    store.insert("source_observations", [{
        "observed_at": observed_at or store.now(), "provider": provider, "source_url": url, "source_kind": kind,
        "content_sha256": digest, "change_id": change_id, "text": text[:200_000], "http_status": status,
        "run_id": run_id,
    }])
    if not prev:
        state = "first_seen"
    elif prev[0][0] == digest:
        state = "unchanged"
    else:
        state = "content_updated"
    return digest, state


# ----------------------------------------------------------------------------- Stripe

def _md_tables(md: str):
    """Yield (section_heading, row_cells) for markdown tables."""
    heading = ""
    for line in md.splitlines():
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
        elif line.startswith("|") and not re.match(r"^\|\s*-", line):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            yield heading, cells


def _link_text(cell: str) -> str:
    return re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", cell).strip()


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def parse_stripe_change(url: str, md: str) -> dict:
    m = re.search(r"/changelog/([a-z]+)/(\d{4}-\d{2}-\d{2})/([a-z0-9-]+)", url)
    train, date, slug = m.groups()
    api_version = f"{date}.{train}"
    title = next((l.lstrip("# ").strip() for l in md.splitlines() if l.startswith("# ")), slug)
    removed, added, sdks = set(), set(), {}
    for heading, cells in _md_tables(md):
        if len(cells) < 3 or cells[1] not in ("Removed", "Added"):
            continue
        params = [p.strip(" `") for p in cells[0].split(",")]
        resource = _snake(_link_text(cells[2]).replace(" ", ""))
        sdks.setdefault(heading, set()).update(params)
        if heading != "REST API":
            continue
        for p in params:
            if cells[1] == "Removed":
                removed.add(f"{resource}.{p}")
            else:
                parent = resource.replace("_item", "")
                added.add(f"{parent}.items.data[].{p}" if resource.endswith("_item") else f"{resource}.{p}")
    impact = re.search(r"## Impact\s+(.*?)(?=\n## )", md, re.S)
    summary = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", impact.group(1)).strip() if impact else title
    return {
        "change_id": f"stripe-{train}-{date}-{slug}",
        "change_kind": "breaking_api",
        "provider": "stripe",
        "ecosystem": None,
        "package": "stripe",
        "title": title,
        "api_version": api_version,
        "affected_api_versions": [f"{api_version} and later in this API train"],
        "min_affected_api_version": api_version,
        "changed_symbols": sorted(removed | added),
        "removed_symbols": sorted(removed),
        "added_symbols": sorted(added),
        "sdk_symbols": {k: sorted(v) for k, v in sdks.items()},
        "source_url": url,
        "published_at": date,
        "summary": summary,
        "verified_source": True,
    }


def watch_stripe(run_id: str, log: store.RunLog) -> list[dict]:
    changes = []
    for url in config.STRIPE_CHANGELOG_URLS:
        with log.stage("source_fetch", "stripe") as st:
            fetched = fetch_text(url + ".md")  # official Markdown rendering of the same page
            change = parse_stripe_change(url, fetched["text"])
            digest, state = observe("stripe", url, "changelog", fetched["text"], fetched["status"], change["change_id"], run_id)
            injected = detect_instruction_like(fetched["text"])
            change.update(content_sha256=digest, observation_state=state, fetched_at=fetched["fetched_at"],
                          source_mode=fetched["source_mode"], http_status=fetched["status"], source_text=fetched["text"],
                          quarantined_instructions=injected)
            st.details = {"url": url, "sha256": digest, "state": state, "mode": fetched["source_mode"],
                          "removed": change["removed_symbols"], "instruction_like_spans": len(injected)}
            changes.append(change)
    return changes


# ----------------------------------------------------------------------------- Shopify

def watch_shopify(run_id: str, log: store.RunLog) -> list[dict]:
    with log.stage("source_fetch", "shopify") as st:
        fetched = fetch_text(config.SHOPIFY_FEED_URL)
        root = ET.fromstring(fetched["text"])
        changes = []
        for item in root.findall(".//item")[: config.SHOPIFY_FEED_LIMIT]:
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            desc = html.unescape(re.sub(r"<[^>]+>", " ", item.findtext("description", "")))
            desc = re.sub(r"\s+", " ", desc).strip()
            cats = [c.text for c in item.findall("category") if c.text]
            versions = [c for c in cats if re.match(r"^\d{4}-\d{2}$", c)]
            try:
                published = parsedate_to_datetime(item.findtext("pubDate", "")).astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:  # noqa: BLE001
                published = store.now()
            text = f"{title}\n\n{desc}"
            slug = link.rstrip("/").rsplit("/", 1)[-1]
            change = {
                "change_id": f"shopify-{slug}"[:120], "change_kind": "api_change", "provider": "shopify",
                "ecosystem": None, "package": "shopify", "title": title, "affected_api_versions": versions,
                "changed_symbols": sorted(set(re.findall(r"`?\b([a-z]+[A-Z_][A-Za-z_]+|[a-z]+_[a-z_]+)\b`?", desc)))[:20],
                "source_url": link, "published_at": published.isoformat(), "summary": desc[:600],
                "categories": cats, "verified_source": True, "source_mode": fetched["source_mode"],
            }
            digest, state = observe("shopify", link, "release_note", text, fetched["status"], change["change_id"], run_id)
            change.update(content_sha256=digest, observation_state=state, quarantined_instructions=detect_instruction_like(text))
            changes.append(change)
        st.details = {"feed": config.SHOPIFY_FEED_URL, "entries": len(changes), "mode": fetched["source_mode"],
                      "new_or_updated": sum(c["observation_state"] != "unchanged" for c in changes)}
    return changes


# ----------------------------------------------------------------------------- OSV

def _severity(vuln: dict) -> str:
    sev = (vuln.get("database_specific") or {}).get("severity")
    if sev:
        return sev.upper()
    for s in vuln.get("severity", []):
        if s.get("type", "").startswith("CVSS"):
            return s["score"].split("/")[0]
    return "UNKNOWN"


def osv_querybatch(packages: list[dict]) -> list[list[str]]:
    queries = [{"package": {"ecosystem": p["ecosystem"], "name": p["name"]}, "version": p["version"]} for p in packages]
    fetched = fetch_text(f"{config.OSV_API}/querybatch", method="POST", json_body={"queries": queries})
    results = json.loads(fetched["text"])["results"]
    return [[v["id"] for v in r.get("vulns", [])] for r in results], fetched


def osv_vuln(vuln_id: str) -> dict:
    fetched = fetch_text(f"{config.OSV_API}/vulns/{vuln_id}")
    vuln = json.loads(fetched["text"])
    vuln["_source_mode"] = fetched["source_mode"]
    return vuln


def watch_osv(packages: list[dict], run_id: str, log: store.RunLog) -> list[dict]:
    """packages: [{ecosystem, name, version, ...}] with RESOLVED versions only."""
    with log.stage("source_fetch", "osv") as st:
        id_lists, fetched = osv_querybatch(packages)
        st.details = {"endpoint": f"{config.OSV_API}/querybatch", "queries": len(packages),
                      "vuln_ids": sum(len(x) for x in id_lists), "mode": fetched["source_mode"]}
    changes, cache = [], {}
    with log.stage("source_fetch", "osv_vulns") as st:
        for pkg, ids in zip(packages, id_lists):
            for vid in ids:
                if vid not in cache:
                    cache[vid] = osv_vuln(vid)
                v = cache[vid]
                canonical = json.dumps({k: v[k] for k in sorted(v) if not k.startswith("_")}, sort_keys=True)
                url = f"https://osv.dev/vulnerability/{vid}"
                aliases = v.get("aliases", [])
                cve = next((a for a in [vid, *aliases] if a.startswith("CVE-")), None)
                change = {
                    "change_id": vid, "change_kind": "vulnerability", "provider": "osv", "ecosystem": pkg["ecosystem"],
                    "package": pkg["name"], "title": v.get("summary") or vid, "cve": cve, "aliases": aliases,
                    "severity": _severity(v), "source_url": url, "published_at": v.get("published"),
                    "modified_at": v.get("modified"), "summary": (v.get("details") or v.get("summary") or "")[:1500],
                    "references": [r["url"] for r in v.get("references", [])][:8], "osv": v,
                    "verified_source": True, "source_mode": v["_source_mode"],
                    "cwes": (v.get("database_specific") or {}).get("cwe_ids", []),
                }
                if not any(c["change_id"] == vid and c["package"] == pkg["name"] for c in changes):
                    digest, state = observe("osv", url, "advisory", canonical, 200, vid, run_id)
                    change.update(content_sha256=digest, observation_state=state)
                    changes.append(change)
        st.details = {"fetched_vulns": len(cache), "changes": len(changes),
                      "updated": [c["change_id"] for c in changes if c["observation_state"] == "content_updated"]}
    return changes


def osv_check_version(ecosystem: str, name: str, version: str) -> list[str]:
    ids, _ = osv_querybatch([{"ecosystem": ecosystem, "name": name, "version": version}])
    return ids[0]
