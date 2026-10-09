#!/usr/bin/env bash
# Start ClickHouse (local), the ML inference service (local instance of the Akash container) and the DriftGuard API/UI.
# Set ML_SERVICE_URL to the Akash endpoint to use the deployed service instead of the local one.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/.tools"; mkdir -p "$TOOLS" "$ROOT/.work"

if [ -z "${CLICKHOUSE_HOST:-}" ] && ! curl -sf "http://localhost:8123/ping" >/dev/null; then
  [ -x "$TOOLS/clickhouse" ] || (cd "$TOOLS" && curl -sSL https://clickhouse.com/ | sh)
  mkdir -p "$TOOLS/chdata"
  (cd "$TOOLS/chdata" && nohup ../clickhouse server -- --path="$TOOLS/chdata/" --http_port=8123 --tcp_port=9000 \
     --mysql_port=0 --postgresql_port=0 --logger.log="$TOOLS/chdata/ch.log" --logger.level=warning > /dev/null 2>&1 &)
  until curl -sf http://localhost:8123/ping >/dev/null; do sleep 1; done
fi
echo "ClickHouse: $(curl -s 'http://localhost:8123/?query=SELECT%20version()' || echo "$CLICKHOUSE_HOST")"

[ -d "$ROOT/.venv" ] || (uv venv -p 3.12 "$ROOT/.venv" && uv pip install -p "$ROOT/.venv/bin/python" -r "$ROOT/requirements.txt")

if [ -z "${ML_SERVICE_URL:-}" ] && ! curl -sf http://localhost:8100/health >/dev/null; then
  (cd "$ROOT/ml_service" && HF_HUB_OFFLINE="${HF_HUB_OFFLINE:-0}" nohup "$ROOT/.venv/bin/uvicorn" app:app --port 8100 > "$ROOT/.work/ml.log" 2>&1 &)
  until curl -sf http://localhost:8100/health >/dev/null; do sleep 2; done
fi
echo "ML service: $(curl -s "${ML_SERVICE_URL:-http://localhost:8100}/health")"

cd "$ROOT" && exec .venv/bin/python -m uvicorn driftguard.api:app --host 127.0.0.1 --port "${PORT:-8080}"
