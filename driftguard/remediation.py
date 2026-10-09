"""Regression proof and remediation playbooks.

For a finding group (one upstream change + its matched call sites) a playbook:
  1. adds regression tests that replay recorded pre-/post-change fixtures (or inert security probes),
  2. runs them against the UNPATCHED code at the scanned SHA (proof: old PASS / new FAIL),
  3. tries candidate patches in isolated worktrees, rejecting any candidate whose tests do not ALL pass
     (a fix that makes the security test pass but breaks a valid use case is rejected),
  4. re-runs Semgrep / OSV on the accepted candidate.
Playbooks are deterministic codemods per change family; they never touch production and never merge.
"""
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import config, github, semgrep_runner, sources, upgrades, versions

TEMPLATES = Path(__file__).parent / "templates"


# ----------------------------------------------------------------------------- test execution

def _run(cmd: list[str], cwd: Path, timeout=600, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})})


def parse_junit(path: Path) -> list[dict]:
    if not path.exists():
        return []
    cases = []
    for tc in ET.parse(path).getroot().iter("testcase"):
        failure = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
        status = "skipped" if tc.find("skipped") is not None else ("fail" if failure is not None else "pass")
        msg = (failure.get("message") or (failure.text or ""))[:400] if failure is not None else ""
        cases.append({"name": tc.get("name"), "file": tc.get("classname") or tc.get("file") or "", "status": status, "message": msg})
    return cases


@dataclass
class TestRun:
    label: str
    command: str
    passed: bool
    cases: list[dict]
    output_tail: str
    duration_ms: float

    def as_dict(self):
        return {"label": self.label, "command": self.command, "passed": self.passed, "cases": self.cases,
                "output_tail": self.output_tail, "duration_ms": round(self.duration_ms)}


def node_tests(app: Path, label: str, pattern: str) -> TestRun:
    report = app / ".driftguard-junit.xml"
    report.unlink(missing_ok=True)
    cmd = ["node", "--test", "--test-reporter=junit", f"--test-reporter-destination={report}",
           "--test-reporter=spec", "--test-reporter-destination=stdout", pattern]
    t0 = time.perf_counter()
    proc = _run(cmd, app)
    cases = parse_junit(report)
    report.unlink(missing_ok=True)
    return TestRun(label, " ".join(cmd[:2] + [pattern]), proc.returncode == 0 and bool(cases), cases,
                   (proc.stdout + proc.stderr)[-2500:], (time.perf_counter() - t0) * 1000)


def py_tests(app: Path, label: str, python: Path) -> TestRun:
    report = app / ".driftguard-junit.xml"
    report.unlink(missing_ok=True)
    cmd = [str(python), "-m", "pytest", "-q", f"--junitxml={report}", "-p", "no:cacheprovider"]
    t0 = time.perf_counter()
    proc = _run(cmd, app)
    cases = parse_junit(report)
    report.unlink(missing_ok=True)
    return TestRun(label, "python -m pytest -q", proc.returncode == 0 and bool(cases), cases,
                   (proc.stdout + proc.stderr)[-2500:], (time.perf_counter() - t0) * 1000)


# ----------------------------------------------------------------------------- source edits

def apply_span_edits(path: Path, edits: list[tuple[int, int, str]]):
    """Replace byte-offset spans (from Semgrep) right-to-left so earlier offsets stay valid."""
    data = path.read_bytes()
    for start, end, text in sorted(edits, key=lambda e: e[0], reverse=True):
        data = data[:start] + text.encode() + data[end:]
    path.write_bytes(data)


def add_ts_import(path: Path, line: str):
    lines = path.read_text().splitlines(keepends=True)
    last = max((i for i, l in enumerate(lines) if l.startswith("import ")), default=-1)
    lines.insert(last + 1, line + "\n")
    path.write_text("".join(lines))


def render(template: str, **kw) -> str:
    text = (TEMPLATES / template).read_text()
    for k, v in kw.items():
        text = text.replace("{{" + k + "}}", str(v))
    return text


def split_args(call: str) -> list[str]:
    inner = call[call.index("(") + 1 : call.rindex(")")]
    args, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        args.append(cur.strip())
    return args


def parse_period_access(code: str) -> tuple[str, str, str | None]:
    """Decompose a matched span: `sub.current_period_end` or `const { current_period_end: alias } = sub;`."""
    m = re.match(r"\s*const\s*\{\s*(current_period_(?:start|end))\s*(?::\s*(\w+))?\s*\}\s*=\s*([\w.]+)\s*;?\s*$", code)
    if m:
        return m.group(3), m.group(1), m.group(2) or m.group(1)
    m = re.match(r"\s*([\w.]+)\.(current_period_(?:start|end))\s*$", code)
    if not m:
        raise ValueError(f"unrecognized Stripe period access: {code!r}")
    return m.group(1), m.group(2), None


# ----------------------------------------------------------------------------- playbooks

@dataclass
class Candidate:
    name: str
    description: str
    apply: Callable[[Path], list[str]]  # returns changed paths (repo-relative)


@dataclass
class Playbook:
    key: str
    title: str
    app_dir: str
    regression_files: dict[str, str]
    setup: Callable[[Path], str | None]  # returns error text or None
    run_tests: Callable[[Path, str], TestRun]
    candidates: list[Candidate]
    accept: Callable[[Path, list[str]], tuple[bool, str]]
    pr_title: str
    notes: list[str] = field(default_factory=list)


def _npm_setup(app_rel: str):
    def setup(wt: Path):
        proc = _run(["npm", "ci", "--no-audit", "--no-fund"], wt / app_rel)
        return None if proc.returncode == 0 else proc.stderr[-1500:]
    return setup


def _venv_python(wt: Path) -> Path:
    return config.WORK_DIR / "venvs" / wt.name / "bin" / "python"


def _py_setup(app_rel: str):
    def setup(wt: Path):
        venv = _venv_python(wt).parent.parent
        shutil.rmtree(venv, ignore_errors=True)
        venv.parent.mkdir(parents=True, exist_ok=True)
        proc = _run(["uv", "venv", "-q", "-p", config.PYTHON_TEST_VERSION, str(venv)], wt)
        if proc.returncode != 0:
            return proc.stderr[-1500:]
        proc = _run(["uv", "pip", "install", "-q", "-p", str(venv / "bin" / "python"), "-r", "requirements.txt", "pytest==8.3.3"], wt / app_rel)
        return None if proc.returncode == 0 else ("dependency install failed:\n" + proc.stderr[-1500:])
    return setup


def stripe_periods_playbook(group: dict) -> Playbook:
    change = group["change"]
    impacted = [f for f in group["findings"] if f["status"] == "impacted" and f.get("semgrep")]
    app_dir = impacted[0]["path"].split("/src/")[0]
    helper_rel = f"{app_dir}/src/stripe/billing-period.ts"

    def edits_for(rewrite):
        def apply(wt: Path):
            by_file: dict[str, list] = {}
            for f in impacted:
                m = f["semgrep"]
                sub, field_name, alias = parse_period_access((wt / f["path"]).read_bytes()[m["start_offset"] : m["end_offset"]].decode())
                by_file.setdefault(f["path"], []).append((m["start_offset"], m["end_offset"], rewrite(sub, field_name, alias)))
            for rel, edits in by_file.items():
                apply_span_edits(wt / rel, edits)
            return sorted(by_file)
        return apply

    def correct(sub, field_name, alias):
        prop = "end" if field_name.endswith("end") else "start"
        return f"const {{ {prop}: {alias} }} = billingPeriod({sub});" if alias else f"billingPeriod({sub}).{prop}"

    def naive(sub, field_name, alias):
        return f"const {{ {field_name}: {alias} }} = {sub}.items.data[0];" if alias else f"{sub}.items.data[0].{field_name}"

    def apply_correct(wt: Path):
        changed = edits_for(correct)(wt)
        (wt / helper_rel).write_text(render("billing-period.ts", change_id=change["change_id"], source_url=change["source_url"]))
        for rel in changed:
            target = os.path.relpath(wt / helper_rel, (wt / rel).parent)
            add_ts_import(wt / rel, f"import {{ billingPeriod }} from '{target if target.startswith('.') else './' + target}';")
        return changed + [helper_rel]

    test_rel = f"{app_dir}/tests/drift/stripe-basil-periods.test.ts"

    def accept(wt: Path, changed: list[str]):
        rescan = semgrep_runner.scan(wt, [p for p in changed if p.endswith(".ts")])
        left = [r for r in rescan["results"] if r["rule_id"] == impacted[0]["semgrep"]["rule_id"]]
        if left:
            return False, f"Semgrep still matches {len(left)} subscription-level period read(s) in patched files"
        return True, f"Semgrep re-scan of {len(changed)} patched files: 0 remaining matches for {impacted[0]['semgrep']['rule_id']}"

    return Playbook(
        key="stripe-basil-periods", title="Read billing periods from the plan's subscription item (Stripe 2025-03-31.basil)",
        app_dir=app_dir,
        regression_files={test_rel: render("stripe_basil_periods.test.ts", change_id=change["change_id"], source_url=change["source_url"])},
        setup=_npm_setup(app_dir),
        run_tests=lambda wt, label: node_tests(wt / app_dir, label, "tests/**/*.test.ts"),
        candidates=[
            Candidate("items-data-0", "Read current_period_* from items.data[0]", edits_for(naive)),
            Candidate("plan-item-lookup", "Resolve the billing period from the subscription item carrying the plan price "
                      "(falls back to subscription-level fields for payloads from endpoints pinned to older versions)", apply_correct),
        ],
        accept=accept,
        pr_title="fix(billing): read Stripe billing periods from subscription items (API 2025-03-31.basil)",
    )


def dependency_playbook(group: dict, kind: str) -> Playbook:
    change, pkg = group["change"], group["package"]
    target_vuln = change["osv"]
    plan = upgrades.select_upgrade(pkg["ecosystem"], pkg["name"], pkg["version"], target_vuln)
    group["upgrade_plan"] = plan
    app_dir = pkg["app_dir"]
    code_findings = [f for f in group["findings"] if f.get("semgrep")]

    def accept_version(wt: Path, changed: list[str], version_getter):
        installed = version_getter(wt)
        affected, why = versions.osv_affects(target_vuln, pkg["ecosystem"], pkg["name"], installed)
        if affected:
            return False, f"installed {pkg['name']} {installed} still affected: {why}"
        remaining = sources.osv_check_version(pkg["ecosystem"], pkg["name"], installed)
        note = f"; OSV still lists {len(remaining)} other advisories: {', '.join(remaining)}" if remaining else "; OSV lists no known advisories"
        return True, f"installed {pkg['name']} {installed} is outside the affected range of {change['change_id']}{note}"

    if kind == "pyyaml":
        def bump(version):
            def apply(wt: Path):
                req = wt / pkg["manifest"]
                req.write_text(re.sub(r"(?im)^(pyyaml)\s*==\s*[^\s#]+", rf"\g<1>=={version}", req.read_text()))
                by_file: dict[str, list] = {}
                for f in code_findings:
                    m = f["semgrep"]
                    code = (wt / f["path"]).read_bytes()[m["start_offset"] : m["end_offset"]].decode()
                    fixed = re.sub(r"\byaml\.full_load_all\(", "yaml.safe_load_all(", code)
                    fixed = re.sub(r"\byaml\.full_load\(", "yaml.safe_load(", fixed)
                    fixed = re.sub(r"\byaml\.load(_all)?\((.*?),\s*Loader\s*=\s*yaml\.(Full|Unsafe)?Loader\s*\)",
                                   lambda mm: f"yaml.safe_load{mm.group(1) or ''}({mm.group(2)})", fixed, flags=re.S)
                    by_file.setdefault(f["path"], []).append((m["start_offset"], m["end_offset"], fixed))
                for rel, edits in by_file.items():
                    apply_span_edits(wt / rel, edits)
                return [pkg["manifest"], *sorted(by_file)]
            return apply

        def installed(wt: Path):
            return _run([str(_venv_python(wt)), "-c", "import yaml; print(yaml.__version__)"], wt).stdout.strip()

        return Playbook(
            key="pyyaml-cve-2020-14343", title=f"Upgrade PyYAML and use safe_load for untrusted input ({change.get('cve')})",
            app_dir=app_dir,
            regression_files={f"{app_dir}/tests/test_driftguard_cve_2020_14343.py": render(
                "test_driftguard_cve_2020_14343.py", change_id=change["change_id"], cve=change.get("cve"), source_url=change["source_url"])},
            setup=_py_setup(app_dir),
            run_tests=lambda wt, label: py_tests(wt / app_dir, label, _venv_python(wt)),
            candidates=[Candidate(f"pyyaml-{v}+safe_load", f"Pin PyYAML=={v} and switch untrusted loads to yaml.safe_load", bump(v))
                        for v in plan["attempt_order"]],
            accept=lambda wt, changed: accept_version(wt, changed, installed),
            pr_title=f"fix(ingestion): PyYAML {change.get('cve')} - safe_load for partner configs",
        )

    if kind == "lodash":
        def shallow(wt: Path):
            by_file: dict[str, list] = {}
            for f in code_findings:
                m = f["semgrep"]
                code = (wt / f["path"]).read_bytes()[m["start_offset"] : m["end_offset"]].decode()
                args = split_args(code)
                by_file.setdefault(f["path"], []).append(
                    (m["start_offset"], m["end_offset"], f"Object.assign({args[0]}, {', '.join(reversed(args[1:]))})"))
            for rel, edits in by_file.items():
                apply_span_edits(wt / rel, edits)
            return sorted(by_file)

        def bump(version):
            def apply(wt: Path):
                proc = _run(["npm", "install", f"lodash@{version}", "--save-exact", "--no-audit", "--no-fund"], wt / app_dir)
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr[-1000:])
                return [f"{app_dir}/package.json", f"{app_dir}/package-lock.json"]
            return apply

        def installed(wt: Path):
            return _run(["node", "-p", "require('lodash/package.json').version"], wt / app_dir).stdout.strip()

        return Playbook(
            key="lodash-cve-2019-10744", title=f"Upgrade lodash past {change.get('cve')} (defaultsDeep prototype pollution)",
            app_dir=app_dir,
            regression_files={f"{app_dir}/tests/driftguard-cve-2019-10744.test.js": render(
                "driftguard-cve-2019-10744.test.js", change_id=change["change_id"], cve=change.get("cve"), source_url=change["source_url"])},
            setup=_npm_setup(app_dir),
            run_tests=lambda wt, label: node_tests(wt / app_dir, label, "tests/**/*.test.js"),
            candidates=[Candidate("shallow-object-assign", "Replace _.defaultsDeep with a shallow Object.assign merge", shallow)]
            + [Candidate(f"lodash-{v}", f"Upgrade lodash to {v} (npm install --save-exact)", bump(v)) for v in plan["attempt_order"]],
            accept=lambda wt, changed: accept_version(wt, changed, installed),
            pr_title=f"fix(account): upgrade lodash to {plan['chosen']} ({change.get('cve')})",
        )
    raise ValueError(kind)


def playbook_for(group: dict) -> Playbook | None:
    rules = {f["semgrep"]["rule_id"] for f in group["findings"] if f.get("semgrep")}
    if "driftguard.stripe.subscription-period-fields-removed-basil" in rules and any(f["status"] == "impacted" for f in group["findings"]):
        return stripe_periods_playbook(group)
    if "driftguard.python.pyyaml-full-loader" in rules:
        return dependency_playbook(group, "pyyaml")
    if "driftguard.js.lodash-defaultsdeep-prototype-pollution" in rules:
        return dependency_playbook(group, "lodash")
    return None


# ----------------------------------------------------------------------------- orchestration

def _write_regressions(wt: Path, pb: Playbook):
    for rel, content in pb.regression_files.items():
        (wt / rel).parent.mkdir(parents=True, exist_ok=True)
        (wt / rel).write_text(content)


def prove(group: dict, repo: str, sha: str, log) -> dict:
    """Run regression tests against the unpatched code at the scanned SHA."""
    pb = playbook_for(group)
    if pb is None:
        return {"status": "no_playbook"}
    with log.stage("regression_proof", pb.key) as st:
        wt = github.worktree(repo, sha, f"{pb.key}-proof")
        err = pb.setup(wt)
        if err:
            st.result = "error"
            st.details = {"setup_error": err[-500:]}
            return {"status": "setup_failed", "error": err, "playbook": pb.key}
        _write_regressions(wt, pb)
        run = pb.run_tests(wt, "unpatched code + DriftGuard regression tests")
        regression_names = _regression_case_names(run, pb)
        failing = [c for c in run.cases if c["status"] == "fail"]
        reproduced = bool(failing) and all(c["name"] in regression_names for c in failing)
        st.details = {"playbook": pb.key, "cases": len(run.cases), "failing": [c["name"] for c in failing], "reproduced": reproduced}
        st.result = "reproduced" if reproduced else "not_reproduced"
    return {"status": "reproduced" if reproduced else "not_reproduced", "playbook": pb.key, "title": pb.title,
            "regression_files": list(pb.regression_files), "run": run.as_dict(), "regression_case_names": sorted(regression_names),
            "upgrade_plan": group.get("upgrade_plan")}


def _regression_case_names(run: TestRun, pb: Playbook) -> set[str]:
    stems = [Path(p).name.split(".")[0] for p in pb.regression_files]
    names = {c["name"] for c in run.cases if any(s in (c.get("file") or "") for s in stems)}
    if not names:  # node junit has no file attribute: recognize DriftGuard cases by their template names
        names = {c["name"] for c in run.cases if c["name"].startswith("[") or "untrusted" in c["name"] or "affected range" in c["name"]}
    return names


def remediate(group: dict, repo: str, sha: str, log) -> dict:
    """Try candidates in isolated worktrees; return the accepted one (if any) with all evidence."""
    pb = playbook_for(group)
    if pb is None:
        return {"status": "no_playbook"}
    attempts, accepted = [], None
    for cand in pb.candidates:
        with log.stage("candidate_patch", pb.key) as st:
            wt = github.worktree(repo, sha, f"{pb.key}-{cand.name}")
            _write_regressions(wt, pb)
            attempt = {"candidate": cand.name, "description": cand.description}
            try:
                changed = cand.apply(wt)
            except Exception as exc:  # noqa: BLE001
                attempt.update(verdict="rejected", reason=f"patch could not be applied: {exc}")
                attempts.append(attempt)
                st.result, st.details = "rejected", attempt
                continue
            err = pb.setup(wt)
            if err:
                attempt.update(verdict="rejected", reason="environment setup failed for this candidate: " + _error_line(err))
                attempts.append(attempt)
                st.result, st.details = "rejected", attempt
                continue
            run = pb.run_tests(wt, f"candidate {cand.name}: full suite")
            attempt["tests"] = run.as_dict()
            attempt["changed_files"] = changed + list(pb.regression_files)
            if not run.passed:
                failing = [c["name"] for c in run.cases if c["status"] == "fail"]
                attempt.update(verdict="rejected", reason="tests failed: " + "; ".join(failing))
            else:
                ok, why = pb.accept(wt, changed)
                attempt.update(verdict="accepted" if ok else "rejected", reason=why)
            attempt["diff"] = github.git("diff", "--stat", cwd=wt) + "\n\n" + _full_diff(wt)
            attempts.append(attempt)
            st.result = attempt["verdict"]
            st.details = {k: v for k, v in attempt.items() if k not in ("tests", "diff")}
            if attempt["verdict"] == "accepted":
                accepted = {"worktree": str(wt), **attempt}
                break
    return {"status": "accepted" if accepted else "no_passing_candidate", "playbook": pb.key, "title": pb.title,
            "pr_title": pb.pr_title, "attempts": attempts, "accepted": accepted, "upgrade_plan": group.get("upgrade_plan"),
            "regression_files": list(pb.regression_files)}


def _error_line(err: str) -> str:
    lines = [l.strip() for l in err.strip().splitlines() if l.strip()]
    keys = ("error:", "Error", "failed", "AttributeError")
    picked = [l for l in lines if any(k in l for k in keys) and not l.endswith(":")]
    return (picked[0] if picked else lines[-1] if lines else "unknown error")[:300]


def _full_diff(wt: Path) -> str:
    github.git("add", "-A", "--", ".", ":(exclude)**/node_modules/**", cwd=wt)
    return github.git("diff", "--cached", cwd=wt)[:60000]
