"""CLI: python -m driftguard investigate | remediate <run_id> <group_key> | serve"""
import json
import sys

from . import config, pipeline


def main(argv):
    cmd = argv[0] if argv else "investigate"
    if cmd == "investigate":
        state = pipeline.investigate(config.DEMO_REPO, config.DEMO_BRANCH, prove="--no-proof" not in argv)
        print(json.dumps({"run_id": state["run_id"], "commit_sha": state["commit_sha"], "counts": state["counts"],
                          "duration_ms": state["duration_ms"]}, indent=2))
        for f in state["findings"]:
            print(f"{f['confidence_tier']:<18} {f['status']:<20} {f['path']}:{f['line']}  {f['change_id']}")
    elif cmd == "remediate":
        rem = {"rem_id": "cli", "run_id": argv[1], "group_key": argv[2], "dry_run": "--dry-run" in argv}
        out = pipeline.remediate(rem)
        print(json.dumps({k: v for k, v in out.items() if k not in ("events", "result")}, indent=2, default=str))
        for e in out.get("events", []):
            if e["stage"] == "pre_pr_rescan":
                print("pre-PR rescan:", e["details"])
        for a in out.get("result", {}).get("attempts", []):
            print(f"  {a['candidate']:<24} {a['verdict']:<9} {a['reason'][:160]}")
    elif cmd == "serve":
        import uvicorn
        uvicorn.run("driftguard.api:app", host="127.0.0.1", port=int(argv[1]) if len(argv) > 1 else 8000)


if __name__ == "__main__":
    main(sys.argv[1:])
