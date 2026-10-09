# DriftGuard: 3-minute demo runbook

Measured on the final audit (2026-10-09). A live run completes in **32–35 s**. The Guild watcher session runs
concurrently: the agent itself takes about 8–13 s, but Guild session dispatch and its events API have taken 15 s to
over 2 min. Its trace attaches to the run when Guild finishes, and the Overview card shows "running" with a live
session link until then.

## Before recording (T-10 min)

1. Check that services are up:
   `curl -s localhost:8123/ping` (ClickHouse) and `curl -s localhost:8080/api/status | python3 -m json.tool`.
   All five should be `ok`, and `ml.deployment` should be `akash`.
   If the API is down: `cd driftguard && .venv/bin/python -m uvicorn driftguard.api:app --port 8080`.
2. Open these tabs in order (browser zoom 90%, notifications off):
   1. http://127.0.0.1:8080/#/overview (DriftGuard Overview)
   2. https://github.com/rishit2121/driftguard-demo-monorepo/pull/4/files (PR #4, Files changed: inline comments)
   3. https://github.com/rishit2121/driftguard-demo-monorepo/issues/5 (Issue #5)
   4. Spare: http://127.0.0.1:8080/#/overview?run=run_20261009_210203_b245e9 (labeled **RECORDED FALLBACK RUN**)
3. Do **not** push to the demo repo right before recording. A new head SHA is fine, but it changes line links and branch names.
4. The Akash deployment has a spend cap and closes around **2026-10-11 20:35 UTC**. After that, extend it in Akash Console or redeploy `ml_service/deploy.yaml`.
5. Record a full backup take. If anything external is slow on the day, use the backup, or say so and switch to the fallback run.

## Script

| Time | Screen | Do | Say |
|---|---|---|---|
| 0:00–0:12 | Overview | Point at the 5 green pills. | "Upstream changes break downstream code. DriftGuard watches official changelogs and advisories, finds the exact lines they hit in your repo, proves it, and opens a verified draft PR." |
| 0:12–0:47 | Overview → **▶ Run live investigation** | Click. The live box streams measured events. | "This is live against our public demo repo. It pins the commit SHA, fetches the official Stripe changelog and OSV, and starts a **Guild** agent session that independently reads our lockfiles and fetches the same sources. Embeddings and ranking come from our model on **Akash**, retrieval is a **ClickHouse** cosineDistance query, and **Semgrep** finds exact lines. Then we replay recorded pre/post fixtures against the real code." When it reloads (~35 s): "Done in 35 seconds." |
| 0:47–1:10 | Headline card | Point at step 1 → 2 → 3. | "Stripe's basil release removed `current_period_end`. Four exact lines are affected. The legacy webhook is pinned to the old API version, so it is an upgrade risk, not broken. On the unpatched code, 4 post-basil tests fail and 12 others pass." |
| 1:10–1:30 | Click `subscription.ts:14` → finding page, scroll to **Vulnerable code → proposed fix** | Red line left, green fix right. | "Red is the vulnerable line Semgrep found. Green is the patch DriftGuard actually tested." |
| 1:30–1:55 | Back to Overview step 3 → tab 2 (PR #4 Files changed) → tab 3 (Issue #5) | Show the REJECTED card, then the inline comment and the Issue. | "The obvious fix, `items.data[0]`, was **rejected**: it broke 12 valid tests. The correct fix passed all 16. The **Guild** remediator agent opened this draft PR. CI is green, there are inline comments on the vulnerable lines, and an Issue links the advisory, the exact lines and the PR. A human merges." |
| 1:55–2:20 | Overview security cards | Point at the REJECTED lines. | "Same pipeline for CVEs in Python and JavaScript. PyYAML 5.4 didn't even install, so it was rejected. For lodash, a shallow merge broke valid behavior, and the minimal patch version still carried 6 advisories, so we chose a clean version. Log4j in Java is shown as a candidate only; we don't claim exploitability." |
| 2:20–2:40 | Evidence cards | Click the Guild **trace ↗** if it shows DONE (or say "running"). | "Every claim links to evidence: the Guild session trace with its 9 tool calls, the Akash pod and latency, ClickHouse query milliseconds and rows read." |
| 2:40–3:00 | Benchmark card + quarantine notice | | "On our benchmark: 7 of 7 impacted scenarios across 4 languages with exact lines, and 0 of 8 false alerts on known-safe cases. It's a small corpus we built. A prompt injection planted in the docs was quarantined, never obeyed. DriftGuard turns internet changes into verified, reviewable fixes." |

## If something goes wrong

| Symptom | Action (say it out loud; never pass recorded data off as live) |
|---|---|
| Live run errors or exceeds about 60 s | Click **open recorded fallback run** in the Overview header. The page shows an amber **RECORDED FALLBACK RUN** badge. "Here's the run we completed earlier today with all five integrations." |
| Guild card still shows "running" | "Guild's session API is slow right now. Here's the live session link." Open the trace, or show the fallback run's completed Guild card. |
| Akash pill red | The run continues without semantic evidence and logs `ml_unavailable`. Say so, and show the fallback run's Akash card. |
| GitHub slow | The PR, Issue and CI tabs are pre-opened. |

## Facts to quote (verified)

- Live run: about 35 s. 26 measured stages in `run_events`. Vector query about 5–20 ms (ClickHouse-reported).
- Akash: about 40–70 ms server time per inference, about 450–800 ms round trip from the US to Sweden.
- Benchmark: 7/7 detected, 7/7 exact lines, 0/8 false alerts, 3/3 version-correct. This is a small, self-built corpus.
- PRs: #4 opened by Guild (`app/guild-ai-platform`). #1–#3 were opened earlier by the disclosed direct-GitHub fallback, before Guild was authorized.
- Issues #5–#7 and the inline review comments were filed via the GitHub API with the operator token, as each Issue footer says.
