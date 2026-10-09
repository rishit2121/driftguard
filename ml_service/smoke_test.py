"""Smoke test for the DriftGuard ML service (stdlib only).

Usage: python smoke_test.py [BASE_URL]   (or env ML_SERVICE_URL; default http://localhost:8100)
Sends `Authorization: Bearer $ML_SERVICE_TOKEN` when that env var is set. Exits non-zero on failure.
"""
import json
import os
import sys
import time
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ML_SERVICE_URL", "http://localhost:8100")).rstrip("/")
TOKEN = os.environ.get("ML_SERVICE_TOKEN")

CHANGE = "CVE-2020-14343: PyYAML < 5.4 full_load / FullLoader allows arbitrary code execution."
VULN = "# PyYAML==5.3.1\ncfg = yaml.load(request.data, Loader=yaml.FullLoader)"
SAFE = "# PyYAML==6.0.1\ncfg = yaml.safe_load(open('config.yml'))"
F_VULN = {"provider_match": 1, "symbol_match": 1, "version_applicable": 1, "semgrep_match": 1, "test_failure": 0}
F_SAFE = {"provider_match": 1, "symbol_match": 1, "version_applicable": 0, "semgrep_match": 0, "test_failure": 0}


def call(method, path, body=None):
    headers = {"Content-Type": "application/json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(BASE + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=60) as r:
        out = json.loads(r.read())
    rtt = (time.perf_counter() - t0) * 1000
    print(f"{method:<4} {path:<10} {rtt:8.1f} ms  model_version={out.get('model_version')}")
    return out


def main():
    print(f"target: {BASE}")
    h = call("GET", "/health")
    assert h["status"] == "ok" and h["embedding_dim"] == 384, h
    print(f"     host={h['host']} deployment={h['deployment']} ranker={h['ranker_version']}")

    e = call("POST", "/embed", {"texts": [CHANGE, VULN]})
    assert len(e["vectors"]) == 2 and len(e["vectors"][0]) == 384
    print(f"     L2 norm={sum(x * x for x in e['vectors'][0]) ** 0.5:.4f} server_ms={e['elapsed_ms']}")

    r = call("POST", "/rank", {"pairs": [
        {"change_text": CHANGE, "code_context": VULN, "explicit_features": F_VULN},
        {"change_text": CHANGE, "code_context": SAFE, "explicit_features": F_SAFE},
        {"change_text": CHANGE, "code_context": SAFE},
    ]})
    print(f"     scores={r['scores']} cosine={r['cosine']}")
    assert r["scores"][0] > r["scores"][1], "vulnerable context should outrank safe context"

    for ctx, feats in ((VULN, F_VULN), (SAFE, F_SAFE)):
        c = call("POST", "/classify", {"change_text": CHANGE, "code_context": ctx, "explicit_features": feats})
        print(f"     kind={c['finding_kind']} label={c['relevance_label']} score={c['score']}")
    print("SMOKE TEST PASSED")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"SMOKE TEST FAILED: {exc!r}")
        sys.exit(1)
