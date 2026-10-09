"""DriftGuard ML inference service: embeddings, relevance ranking and a coarse finding classifier."""
import hmac
import json
import logging
import os
import re
import socket
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from common import embed, embed_model_name, embedding_dim, feature_matrix, load_embedder, pair_cosines

SERVICE_VERSION = "0.1.0"
MAX_ITEMS = 256
RANKER_PATH = Path(os.environ.get("RANKER_PATH", Path(__file__).parent / "models" / "ranker.joblib"))
IMPACTED_AT, UNAFFECTED_BELOW = 0.75, 0.35
LIMITATIONS = (
    "Score is a relevance rank, NOT a calibrated exploit probability. It comes from a logistic-regression ranker "
    "trained on ~100 hand-annotated synthetic pairs; treat 'impacted' as 'review first', and confirm with "
    "version checks, static analysis, or tests before acting."
)

log = logging.getLogger("driftguard.ml")
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.INFO)
log.propagate = False

state: dict = {}


@asynccontextmanager
async def lifespan(_: FastAPI):
    bundle = joblib.load(RANKER_PATH)
    name = embed_model_name()
    model = load_embedder(name)
    state.update(embedder=model, embed_name=name, dim=embedding_dim(model), ranker=bundle["model"],
                 ranker_version=bundle["ranker_version"], model_version=f"driftguard-ml-{SERVICE_VERSION}+{bundle['ranker_version']}")
    if bundle.get("embedding_model") != name:
        log.warning(json.dumps({"event": "embed_model_mismatch", "ranker_trained_with": bundle.get("embedding_model"), "serving": name}))
    log.info(json.dumps({"event": "startup", "model_version": state["model_version"], "embedding_model": name}))
    yield
    state.clear()


app = FastAPI(title="DriftGuard ML", version=SERVICE_VERSION, lifespan=lifespan)


def require_token(authorization: str | None = Header(default=None)):
    token = os.environ.get("ML_SERVICE_TOKEN")
    if not token:
        return
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="invalid or missing bearer token")


def log_prediction(endpoint: str, n: int, t0: float) -> float:
    elapsed = round((time.perf_counter() - t0) * 1000, 2)
    log.info(json.dumps({"endpoint": endpoint, "n": n, "elapsed_ms": elapsed, "model_version": state["model_version"]}))
    return elapsed


class ExplicitFeatures(BaseModel):
    provider_match: int = Field(0, ge=0, le=1)
    symbol_match: int = Field(0, ge=0, le=1)
    version_applicable: int = Field(0, ge=0, le=1)
    semgrep_match: int = Field(0, ge=0, le=1)
    test_failure: int = Field(0, ge=0, le=1)


class Pair(BaseModel):
    change_text: str
    code_context: str
    explicit_features: ExplicitFeatures = Field(default_factory=ExplicitFeatures)


class EmbedRequest(BaseModel):
    texts: list[str] = Field(min_length=1, max_length=MAX_ITEMS)


class RankRequest(BaseModel):
    pairs: list[Pair] = Field(min_length=1, max_length=MAX_ITEMS)


def rank_pairs(pairs: list[Pair]):
    cos = pair_cosines(state["embedder"], [p.change_text for p in pairs], [p.code_context for p in pairs])
    X = feature_matrix(cos, [p.explicit_features.model_dump() for p in pairs])
    return state["ranker"].predict_proba(X)[:, 1], cos


def finding_kind(text: str) -> str:
    t = text.lower()
    if re.search(r"\bcve-\d{4}-\d+|\bghsa-|vulnerab", t):
        return "vulnerable_dependency"
    if re.search(r"removed|deprecat|breaking|api version", t):
        return "breaking_api"
    return "unknown"


@app.get("/health")
def health():
    return {"status": "ok", "model_version": state["model_version"], "embedding_model": state["embed_name"],
            "embedding_dim": state["dim"], "ranker_version": state["ranker_version"], "host": socket.gethostname(),
            "deployment": os.environ.get("DEPLOYMENT_TARGET", "local")}


@app.post("/embed", dependencies=[Depends(require_token)])
def embed_texts(req: EmbedRequest):
    t0 = time.perf_counter()
    vecs = embed(state["embedder"], req.texts)
    return {"vectors": vecs.round(6).tolist(), "model_version": state["model_version"],
            "elapsed_ms": log_prediction("embed", len(req.texts), t0)}


@app.post("/rank", dependencies=[Depends(require_token)])
def rank(req: RankRequest):
    t0 = time.perf_counter()
    scores, cos = rank_pairs(req.pairs)
    return {"scores": [round(float(s), 6) for s in scores], "cosine": [round(float(c), 6) for c in cos],
            "model_version": state["model_version"], "ranker_version": state["ranker_version"],
            "elapsed_ms": log_prediction("rank", len(req.pairs), t0)}


@app.post("/classify", dependencies=[Depends(require_token)])
def classify(req: Pair):
    t0 = time.perf_counter()
    score = float(rank_pairs([req])[0][0])
    label = "impacted" if score >= IMPACTED_AT else "unaffected" if score < UNAFFECTED_BELOW else "review"
    return {"finding_kind": finding_kind(req.change_text), "relevance_label": label, "score": round(score, 6),
            "limitations": LIMITATIONS, "model_version": state["model_version"],
            "ranker_version": state["ranker_version"], "elapsed_ms": log_prediction("classify", 1, t0)}
