"""Client for the DriftGuard inference service (deployed on Akash; same container can run locally).

There is no silent fallback: if the service is down, semantic evidence is marked unavailable for the run.
"""
import time

import httpx

from . import config


class MLService:
    def __init__(self, base_url: str = config.ML_SERVICE_URL, token: str = config.ML_SERVICE_TOKEN):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.calls: list[dict] = []

    def _post(self, path: str, body: dict, timeout: float = 120.0) -> dict:
        t0 = time.perf_counter()
        r = httpx.post(f"{self.base_url}{path}", json=body, headers=self.headers, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        self.calls.append({"endpoint": path, "roundtrip_ms": round((time.perf_counter() - t0) * 1000, 1),
                           "server_ms": data.get("elapsed_ms"), "model_version": data.get("model_version"),
                           "n": len(body.get("texts", body.get("pairs", [1])))})
        return data

    def health(self) -> dict:
        t0 = time.perf_counter()
        r = httpx.get(f"{self.base_url}/health", timeout=15)
        r.raise_for_status()
        return {**r.json(), "roundtrip_ms": round((time.perf_counter() - t0) * 1000, 1), "url": self.base_url}

    def embed(self, texts: list[str]) -> tuple[list[list[float]], str]:
        vectors, version = [], None
        for i in range(0, len(texts), 64):
            data = self._post("/embed", {"texts": texts[i : i + 64]})
            vectors += data["vectors"]
            version = data["model_version"]
        return vectors, version

    def rank(self, pairs: list[dict]) -> dict:
        return self._post("/rank", {"pairs": pairs})

    def classify(self, change_text: str, code_context: str, features: dict) -> dict:
        return self._post("/classify", {"change_text": change_text, "code_context": code_context, "explicit_features": features})
