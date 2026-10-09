# DriftGuard ranker training data

`pairs.jsonl` — 104 **hand-annotated synthetic pairs written by the DriftGuard team; not real customer code.**
Change texts paraphrase public changelogs / advisories (Stripe, Shopify, Google Workspace, Twilio, GitHub API,
AWS SDKs, PyYAML, lodash, Log4j, Jinja2, requests, Express, Django, minimist). Code contexts are short
illustrative TS/JS/Python/Java/config snippets invented for this dataset.

One JSON object per line:

| field | meaning |
|---|---|
| `change_id` | `<provider-prefix>-NNN` |
| `provider` | upstream provider / package (used for the held-out-provider split) |
| `change_text` | upstream change or advisory summary |
| `code_context` | candidate code snippet (with version hints in comments) |
| `explicit_features` | `provider_match`, `symbol_match`, `version_applicable`, `semgrep_match`, `test_failure` (0/1) as an annotator believes the upstream scanners would emit them |
| `label` | `applicable` (45), `not_applicable` (45), `uncertain` (14) |

Deliberately included: hard negatives (same field name on an unrelated object, `safe_load` vs `full_load`,
pinned pre-change API versions, fixed library versions, dev-only / test-only dependencies, look-alike APIs such as
`node:util.parseArgs`), hard positives that pattern rules miss (import aliases, computed keys, transitive
dependencies, vendored copies), and noisy features (e.g. `symbol_match=1` on unaffected code, unrelated test failures).
`uncertain` rows are excluded from training and only scored for reporting.

Limitations: small, single-annotator, synthetic; feature values are not produced by real scanners. Do not read
metrics trained on this file as production accuracy.
