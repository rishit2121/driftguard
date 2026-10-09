# DriftGuard ML service

CPU-only FastAPI service that embeds text with `sentence-transformers/all-MiniLM-L6-v2` (384-d, L2-normalized) and
ranks how relevant an upstream change (API deprecation, CVE, advisory) is to a piece of code.

The ranker is a logistic regression over six features: the cosine similarity between the change text and the code
context, plus five explicit 0/1 features from the other DriftGuard scanners (`provider_match`, `symbol_match`,
`version_applicable`, `semgrep_match`, `test_failure`).

> **The score is a relevance rank, not a calibrated probability** that the code is exploitable or will break. The
> ranker was trained on ~100 hand-written synthetic pairs (see `data/README.md`).

## Endpoints

| method | path | body | returns |
|---|---|---|---|
| GET | `/health` | none | `status, model_version, embedding_model, embedding_dim, ranker_version, host, deployment` |
| POST | `/embed` | `{"texts": [str, ...]}` (1 to 256 texts) | `vectors` (384 floats each, L2-normalized), `model_version`, `elapsed_ms` |
| POST | `/rank` | `{"pairs": [{"change_text", "code_context", "explicit_features": {...}}]}` (1 to 256 pairs) | `scores` (0..1), `cosine`, `model_version`, `ranker_version`, `elapsed_ms` |
| POST | `/classify` | `{"change_text", "code_context", "explicit_features": {...}}` | `finding_kind`, `relevance_label`, `score`, `limitations`, `model_version` |

- Explicit features that are missing default to 0. Any value other than 0 or 1 returns HTTP 422.
- `finding_kind` comes from a keyword heuristic on `change_text`:
  - CVE, GHSA or "vulnerab" gives `vulnerable_dependency`.
  - "removed", "deprecat", "breaking" or "api version" gives `breaking_api`.
  - Anything else gives `unknown`.
- `relevance_label` is set by the score:
  - `impacted` when the score is 0.75 or higher.
  - `unaffected` when the score is below 0.35.
  - `review` otherwise.
- **Auth:** if `ML_SERVICE_TOKEN` is set, every POST endpoint needs `Authorization: Bearer <token>`. `/health` stays open.
- Each prediction writes one JSON line to stdout, for example:
  `{"endpoint": "rank", "n": 3, "elapsed_ms": 17.5, "model_version": "..."}`.

### Environment variables

| variable | default | purpose |
|---|---|---|
| `EMBED_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | embedding model (the ranker was trained with the default model) |
| `ML_SERVICE_TOKEN` | unset | turns on bearer auth for the POST endpoints |
| `DEPLOYMENT_TARGET` | `local` | value reported by `/health` |
| `RANKER_PATH` | `models/ranker.joblib` | path to the ranker bundle |

## Run locally

Run these from the `ml_service/` directory. The repo venv already has the dependencies.

```bash
HF_HUB_OFFLINE=1 ../.venv/bin/uvicorn app:app --port 8100
../.venv/bin/python smoke_test.py                 # or: ML_SERVICE_URL=http://host:port python smoke_test.py
curl -s localhost:8100/health
curl -s localhost:8100/classify -H 'content-type: application/json' \
  -d '{"change_text":"CVE-2021-44906 minimist < 1.2.6 prototype pollution","code_context":"const argv = require(\"minimist\")(process.argv)","explicit_features":{"provider_match":1,"version_applicable":1}}'
```

## Train

```bash
../.venv/bin/python train_ranker.py          # --test-providers shopify,log4j,jinja2 (default)
```

The script:

1. Embeds every pair.
2. Holds out every pair from the **shopify, log4j and jinja2** providers as the test set. Pairs labeled `uncertain` are left out of training and scored only for reporting.
3. Trains the full model and two ablations: one without `cosine` and one without `semgrep_match`.
4. Also reports a pooled leave-one-provider-out estimate, which is less noisy than the 22-row test set.
5. Writes `models/ranker.joblib` and `models/metrics.json`.

The ranker version has the form `lr-<YYYYMMDD>-<first 8 chars of data sha256>`. A fixed `random_state` and the absence of shuffling make the metrics deterministic for the same data.

## Docker

```bash
docker build --platform linux/amd64 -t ghcr.io/rishit2121/driftguard-ml:0.1.0 .
docker run --rm -p 8000:8000 -e ML_SERVICE_TOKEN=dev ghcr.io/rishit2121/driftguard-ml:0.1.0
ML_SERVICE_TOKEN=dev python smoke_test.py http://localhost:8000
```

- The image installs the CPU-only torch wheel from `https://download.pytorch.org/whl/cpu`.
- MiniLM is downloaded during the build and baked into the image. At runtime `HF_HUB_OFFLINE=1`, so the container needs no network access to Hugging Face.
- `models/ranker.joblib` must exist before you build. Run training first.
- Use `--platform linux/amd64` on Apple Silicon, because Akash providers run x86_64.

Push the image to GHCR:

```bash
echo "$GITHUB_PAT" | docker login ghcr.io -u rishit2121 --password-stdin
docker push ghcr.io/rishit2121/driftguard-ml:0.1.0
```

Make the package public in GitHub (Packages → driftguard-ml → Package settings → Change visibility). The other option is to add registry `credentials` to the service in `deploy.yaml`.

## Deploy on Akash (Akash Console)

1. Edit `deploy.yaml`: set `ML_SERVICE_TOKEN` to a long random secret, for example the output of `openssl rand -hex 32`.
2. Open https://console.akash.network, connect a wallet (Keplr or Leap) or use a Console trial/credit-card account, and make sure it is funded.
3. Choose **Deploy** → **Build your template**, switch to the YAML editor, paste `deploy.yaml`, then choose **Create Deployment** and approve the deposit transaction.
4. Choose a provider bid and **Accept Bid**, then wait until the lease is active. Check the **Logs** tab for the `startup` JSON line.
5. Copy the URI from the **Leases** tab, which looks like `xxxx.ingress.<provider>.com`. Then verify the deployment:

   ```bash
   curl -s http://<lease-uri>/health    # expect "deployment": "akash"
   ML_SERVICE_TOKEN=<secret> python smoke_test.py http://<lease-uri>
   ```

**SDL notes:**

- The profile is 2 vCPU, 3 GiB RAM and 6 GiB storage. Container port 8000 is exposed as global port 80.
- `signedBy` limits bids to audited providers. It is optional, and you can delete it if you get no bids.
- Pricing uses `uakt`. Since the 2026 Burn-Mint Equilibrium upgrade, the Akash docs default to `uact`, a USD-pegged compute credit. The alternative is shown in a comment in `deploy.yaml`.
- The file validates against the official SDL schema (`akash-network/chain-sdk` `go/sdl/sdl-input.schema.yaml`).

## Files

| file | purpose |
|---|---|
| `app.py` | FastAPI service |
| `common.py` | shared embedding and feature code (used by the service and by training) |
| `train_ranker.py` | training and evaluation |
| `data/pairs.jsonl` | annotated pairs (see `data/README.md`) |
| `models/ranker.joblib` | trained ranker |
| `models/metrics.json` | metrics |
| `smoke_test.py` | end-to-end check against any base URL |
| `Dockerfile`, `.dockerignore`, `requirements.txt` | container build |
| `deploy.yaml` | Akash SDL v2.0 |
