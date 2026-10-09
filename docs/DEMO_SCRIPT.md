# DriftGuard: 3-minute demo script

Setup before recording: `./scripts/start.sh`, open http://127.0.0.1:8080, and have these tabs ready:
the demo repo, PR #4, the Guild session for the latest run, and the Stripe changelog. Record a local backup video.
If an upstream site is slow, the UI labels any cached snapshot as `cached_snapshot`. Never substitute cached data
silently.

| Time | Screen | Say / do |
|---|---|---|
| 0:00–0:15 | **Repositories** page | "Changes upstream can break code downstream." Show `rishit2121/driftguard-demo-monorepo` (TS, JS, Python, Java), the last scanned SHA, 30 packages, 1 unverified version, and the Stripe API version gates: client `basil`, webhook `/webhooks/stripe` `basil`, legacy endpoint `acacia`. |
| 0:15–0:40 | Click **Run full investigation** | The live timeline streams. First the Guild watcher session (pins the SHA, reads lockfiles via Guild GitHub, fetches Stripe + OSV via Guild fetch). Then the platform's own fetches. Click the Guild session link and the Stripe source URL. Point at the content hash and "same sha256 via Guild watcher". |
| 0:40–1:05 | **Changes → Breaking API changes**, then the Stripe finding | Show the ClickHouse retrieval card (cosineDistance over Akash embeddings, ms and rows read). Semgrep pinpoints `apps/billing-ts/src/stripe/subscription.ts:14`. In the baseline, the look-alike `unused-field.ts` ranks on similarity but is excluded by the hard filter. |
| 1:05–1:30 | Finding page, **Regression proof** | Pre-version (`acacia`) fixtures PASS and post-version (`basil`) fixtures FAIL. In "Other locations", `legacy-webhook.ts` is **Upgrade risk**, not broken, because its endpoint is pinned to `acacia`. |
| 1:30–1:55 | **Remediation** card / PR #4 | The `items.data[0]` candidate is REJECTED: it breaks valid cases. `plan-item-lookup` is ACCEPTED and the Semgrep re-scan finds 0 matches. Open PR #4: opened by `app/guild-ai-platform` (Guild remediator), a draft, with citations, before/after tables and 5 green CI checks. |
| 1:55–2:25 | **Security advisories** tab | PyYAML CVE-2020-14343 (`import_config.py:9,20`) is Confirmed, and `trusted_config.py` (safe_load) is listed under "correctly did not match". lodash CVE-2019-10744 is Confirmed. On PR #3 the shallow `Object.assign` candidate was rejected, and 4.17.12 was not chosen because OSV still lists 6 advisories, so 4.18.1 was picked. minimist shows as dev-only inventory exposure. |
| 2:25–2:45 | Log4j finding, then the **Investigation** page | `RequestAudit.java:21` is a **Candidate**: version affected, use site found, exploitability explicitly not proven. Show ClickHouse analytics with real p50/p95 latency and rows read, the dedupe table, the Akash `/health` model id and latency, and the Semgrep rule YAML. |
| 2:45–3:00 | Back to the repo / PR list | "We bridge the gap between internet changes and the exact code they impact, and take verifiable action. Humans approve every merge." |

Numbers to quote (from the latest `benchmark/benchmark_report.json`): 7/7 impacted scenarios detected with exact
lines across 4 languages, and 0/8 false alerts on known-safe cases. This is a small hand-built corpus, so say so.
