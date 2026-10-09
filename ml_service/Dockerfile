# DriftGuard ML inference service (CPU only).
# Build for Akash (x86_64 providers):  docker build --platform linux/amd64 -t ghcr.io/rishit2121/driftguard-ml:0.1.0 .
FROM python:3.11-slim

ARG TORCH_VERSION=2.14.1
ARG EMBED_MODEL=sentence-transformers/all-MiniLM-L6-v2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/opt/hf \
    EMBED_MODEL=${EMBED_MODEL}

WORKDIR /app

# CPU-only torch first so sentence-transformers does not pull the CUDA build.
RUN pip install --index-url https://download.pytorch.org/whl/cpu "torch==${TORCH_VERSION}"
COPY requirements.txt .
RUN pip install -r requirements.txt

# Bake the embedding model into the image so the container needs no Hugging Face access at runtime.
RUN python -c "import os; from sentence_transformers import SentenceTransformer; SentenceTransformer(os.environ['EMBED_MODEL'], device='cpu')"
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1

COPY common.py app.py ./
COPY models/ranker.joblib models/ranker.joblib

RUN useradd --system --uid 10001 app && chown -R app /app /opt/hf
USER app

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
