"""Code usage extraction -> embeddings (Akash service) -> ClickHouse code_symbols, plus vector retrieval."""
import re
from pathlib import Path

from . import store
from .inventory import walk

LANG = {".ts": "typescript", ".js": "javascript", ".py": "python", ".java": "java"}
BLOCK_START = {
    "typescript": re.compile(r"^(export\s+)?(async\s+)?function\s+(\w+)|^(export\s+)?const\s+(\w+)\s*=\s*(async\s*)?\("),
    "javascript": re.compile(r"^(export\s+)?(async\s+)?function\s+(\w+)|^(export\s+)?const\s+(\w+)\s*=\s*(async\s*)?\("),
    "python": re.compile(r"^(async\s+)?def\s+(\w+)|^class\s+(\w+)"),
    "java": re.compile(r"^\s{4}(public|private|protected)\s+(static\s+)?[\w<>\[\]]+\s+(\w+)\s*\("),
}
# import name -> inventory package name
IMPORT_MAP = {"stripe": "stripe", "lodash": "lodash", "yaml": "pyyaml", "org.apache.logging.log4j": "org.apache.logging.log4j:log4j-core",
              "jinja2": "jinja2", "minimist": "minimist"}


def imported_packages(text: str, lang: str) -> list[str]:
    found = set()
    if lang in ("typescript", "javascript"):
        mods = re.findall(r"""(?:from\s+|require\()\s*['"]([^'"]+)['"]""", text)
    elif lang == "python":
        mods = re.findall(r"^\s*(?:import|from)\s+([\w.]+)", text, re.M)
    else:
        mods = re.findall(r"^import\s+([\w.]+)", text, re.M)
    for m in mods:
        for prefix, pkg in IMPORT_MAP.items():
            if m == prefix or m.startswith(prefix + ".") or m.startswith(prefix + "/"):
                found.add(pkg)
    return sorted(found)


def extract_blocks(root: Path) -> list[dict]:
    blocks = []
    for f in walk(root, ("*.ts", "*.js", "*.py", "*.java")):
        rel = str(f.relative_to(root))
        if "/tests/" in f"/{rel}" or "/test/" in f"/{rel}" or rel.startswith(("fixtures/", "benchmark/", ".semgrep/")):
            continue
        lang = LANG[f.suffix]
        text = f.read_text()
        lines = text.splitlines()
        if not text.strip():
            continue
        pkgs = imported_packages(text, lang) or [""]
        starts = []
        for i, line in enumerate(lines):
            m = BLOCK_START[lang].match(line)
            if m:
                starts.append((i, next(g for g in reversed(m.groups()) if g and re.match(r"^\w+$", g) and g not in ("export", "async", "public", "private", "protected", "static"))))
        if not starts:
            starts = [(0, Path(rel).stem)]
        for idx, (s, name) in enumerate(starts):
            e = (starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)) - 1
            while e > s and not lines[e].strip():
                e -= 1
            body = "\n".join(lines[s : e + 1])
            for pkg in pkgs:
                blocks.append({"path": rel, "start_line": s + 1, "end_line": e + 1, "language": lang, "package": pkg,
                               "symbol": name, "usage_context": f"// {rel} ({lang})\n{body}"[:4000]})
    return blocks


def index_repo(root: Path, repo: str, sha: str, ml, log) -> dict:
    with log.stage("code_index", "clickhouse") as st:
        existing = store.client().query(
            "SELECT count() FROM code_symbols WHERE repo={r:String} AND commit_sha={s:String}",
            parameters={"r": repo, "s": sha}).result_rows[0][0]
        blocks = extract_blocks(root)
        if existing:
            st.details = {"commit_sha": sha, "blocks": existing, "reused_index": True}
            return {"blocks": existing, "reused": True}
        vectors, version = ml.embed([b["usage_context"] for b in blocks])
        store.insert("code_symbols", [{"repo": repo, "commit_sha": sha, **b, "embedding": v, "embedding_model": version}
                                      for b, v in zip(blocks, vectors)])
        st.details = {"commit_sha": sha, "blocks": len(blocks), "embedding_model": version, "files": len({b['path'] for b in blocks})}
    return {"blocks": len(blocks), "reused": False, "embedding_model": version}


def index_changes(changes: list[dict], ml, log) -> str | None:
    """Embed change text into doc_chunks (dedup by change_id + content hash)."""
    with log.stage("doc_index", "clickhouse") as st:
        have = {r[0] for r in store.client().query("SELECT id FROM doc_chunks").result_rows}
        todo = [c for c in changes if f"{c['change_id']}:{c['content_sha256'][:12]}" not in have]
        if not todo:
            st.details = {"new_chunks": 0, "known": len(changes)}
            return None
        texts = [change_text(c) for c in todo]
        vectors, version = ml.embed(texts)
        rows = []
        for c, t, v in zip(todo, texts, vectors):
            published = str(c.get("published_at") or "")[:19].replace("T", " ") or "1970-01-01 00:00:00"
            if len(published) == 10:
                published += " 00:00:00"
            rows.append({"id": f"{c['change_id']}:{c['content_sha256'][:12]}", "provider": c["provider"],
                         "change_id": c["change_id"], "source_url": c["source_url"],
                         "published_at": store.datetime.fromisoformat(published),
                         "affected_package": c.get("package") or "",
                         "affected_version": c.get("min_affected_api_version") or ",".join(c.get("affected_api_versions") or []),
                         "symbols": c.get("changed_symbols") or [], "content": t, "embedding": v, "embedding_model": version})
        store.insert("doc_chunks", rows)
        st.details = {"new_chunks": len(rows), "embedding_model": version}
    return version


def change_text(c: dict) -> str:
    syms = ", ".join(c.get("removed_symbols") or c.get("changed_symbols") or [])
    return f"{c['provider']} {c.get('package') or ''}: {c.get('title', '')}\nSymbols: {syms}\n{c.get('summary', '')}"[:3000]


VECTOR_SQL = """
SELECT repo, path, start_line, end_line, symbol, usage_context,
       cosineDistance(embedding, {change_vector:Array(Float32)}) AS distance
FROM code_symbols
WHERE repo = {repo:String} AND commit_sha = {sha:String}
  AND package = {package:String}
ORDER BY distance ASC
LIMIT {k:UInt32}
"""

UNFILTERED_VECTOR_SQL = """
SELECT repo, path, start_line, end_line, symbol, usage_context,
       cosineDistance(embedding, {change_vector:Array(Float32)}) AS distance
FROM code_symbols
WHERE repo = {repo:String} AND commit_sha = {sha:String}
ORDER BY distance ASC
LIMIT {k:UInt32}
"""


def retrieve(change: dict, repo: str, sha: str, ml, run_id: str, k: int = 20) -> dict:
    vec, _ = ml.embed([change_text(change)])
    params = {"change_vector": vec[0], "repo": repo, "sha": sha, "package": change.get("package") or "", "k": k}
    filtered = store.timed_query("vector_candidates_filtered", VECTOR_SQL, params, run_id)
    baseline = store.timed_query("vector_candidates_unfiltered", UNFILTERED_VECTOR_SQL, {**params, "k": 12}, run_id)
    return {"filtered": filtered, "unfiltered": baseline, "vector": vec[0]}
