"""Train the DriftGuard relevance ranker (logistic regression over cosine + explicit features).

Usage: python train_ranker.py [--data data/pairs.jsonl] [--test-providers shopify,log4j,jinja2]
Writes models/ranker.joblib and models/metrics.json. Deterministic (fixed random_state, no shuffling).
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from common import FEATURE_NAMES, embed_model_name, feature_matrix, load_embedder, pair_cosines

HERE = Path(__file__).parent
SEED = 0
VARIANTS = {"full": (), "no_cosine": ("cosine",), "no_semgrep_match": ("semgrep_match",)}


def make_model():
    return make_pipeline(StandardScaler(), LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=SEED))


def scores(y, p):
    yhat = (p >= 0.5).astype(int)
    return {
        "accuracy": round(accuracy_score(y, yhat), 4),
        "precision": round(precision_score(y, yhat, zero_division=0), 4),
        "recall": round(recall_score(y, yhat, zero_division=0), 4),
        "f1": round(f1_score(y, yhat, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y, p), 4) if len(set(y)) > 1 else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(HERE / "data/pairs.jsonl"))
    ap.add_argument("--test-providers", default="shopify,log4j,jinja2")
    ap.add_argument("--out", default=str(HERE / "models"))
    args = ap.parse_args()

    raw = Path(args.data).read_bytes()
    data_sha = hashlib.sha256(raw).hexdigest()
    rows = [json.loads(l) for l in raw.decode().splitlines() if l.strip()]
    test_providers = set(args.test_providers.split(","))

    model_name = embed_model_name()
    print(f"embedding {len(rows)} pairs with {model_name} ...")
    cos = pair_cosines(load_embedder(model_name), [r["change_text"] for r in rows], [r["code_context"] for r in rows])
    explicit = [r.get("explicit_features", {}) for r in rows]
    labels = np.array([r["label"] for r in rows])
    providers = np.array([r["provider"] for r in rows])

    lab = labels != "uncertain"
    y = (labels == "applicable").astype(int)
    tr = lab & ~np.isin(providers, list(test_providers))
    te = lab & np.isin(providers, list(test_providers))
    unc = ~lab

    results, models = {}, {}
    for name, drop in VARIANTS.items():
        X = feature_matrix(cos, explicit, drop)
        m = make_model().fit(X[tr], y[tr])
        models[name] = m
        # Secondary estimate: leave-one-provider-out over all labeled rows (pooled predictions).
        lopo = np.zeros(lab.sum())
        Xl, yl, gl = X[lab], y[lab], providers[lab]
        for a, b in LeaveOneGroupOut().split(Xl, yl, gl):
            lopo[b] = make_model().fit(Xl[a], yl[a]).predict_proba(Xl[b])[:, 1]
        results[name] = {
            "features": [f for f in FEATURE_NAMES if f not in drop],
            "held_out_provider_test": scores(y[te], m.predict_proba(X[te])[:, 1]),
            "leave_one_provider_out_pooled": scores(yl, lopo),
        }

    full = models["full"]
    lr = full[-1]
    p_unc = full.predict_proba(feature_matrix(cos, explicit)[unc])[:, 1]
    version = f"lr-{dt.date.today():%Y%m%d}-{data_sha[:8]}"
    metrics = {
        "ranker_version": version,
        "embedding_model": model_name,
        "data": {"path": os.path.relpath(args.data, HERE), "sha256": data_sha, "n_total": len(rows),
                 "n_uncertain_excluded": int(unc.sum())},
        "split": {"type": "held-out providers", "test_providers": sorted(test_providers),
                  "n_train": int(tr.sum()), "n_test": int(te.sum()),
                  "train_positive": int(y[tr].sum()), "test_positive": int(y[te].sum())},
        "model": "StandardScaler + LogisticRegression(C=1.0, class_weight=balanced, random_state=0); trained on train split only",
        "decision_threshold_for_metrics": 0.5,
        "variants": results,
        "full_model_coefficients_standardized": dict(zip(FEATURE_NAMES, np.round(lr.coef_[0], 4).tolist())),
        "uncertain_rows": {"n": int(unc.sum()), "mean_score": round(float(p_unc.mean()), 4) if unc.any() else None,
                           "scores": {r["change_id"]: round(float(p), 4) for r, p in zip(np.array(rows)[unc], p_unc)}},
        "caveats": [
            "Small-sample estimate: ~100 hand-written synthetic pairs, test set of ~20 rows; expect wide variance.",
            "Scores are relevance ranks from logistic regression, NOT calibrated probabilities of exploitability or breakage.",
            "Explicit features are annotator-assigned, not produced by live scanners.",
        ],
    }
    out = Path(args.out)
    out.mkdir(exist_ok=True)
    joblib.dump({"model": full, "ranker_version": version, "feature_names": FEATURE_NAMES,
                 "embedding_model": model_name, "data_sha256": data_sha}, out / "ranker.joblib")
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")

    print(f"ranker_version={version}  train={tr.sum()}  test={te.sum()}  uncertain_excluded={unc.sum()}")
    print(f"{'variant':<18}{'split':<8}{'acc':>7}{'prec':>7}{'rec':>7}{'f1':>7}{'auc':>7}")
    for name, r in results.items():
        for split, key in (("test", "held_out_provider_test"), ("lopo", "leave_one_provider_out_pooled")):
            s = r[key]
            print(f"{name:<18}{split:<8}" + "".join(f"{s[k] if s[k] is not None else float('nan'):>7.3f}"
                                                for k in ("accuracy", "precision", "recall", "f1", "roc_auc")))


if __name__ == "__main__":
    main()
