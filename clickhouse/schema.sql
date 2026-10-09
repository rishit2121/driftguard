CREATE TABLE IF NOT EXISTS source_observations (
  observed_at DateTime64(3), provider LowCardinality(String),
  source_url String, source_kind LowCardinality(String),
  content_sha256 String, change_id String, text String,
  http_status UInt16, run_id String
) ENGINE = MergeTree ORDER BY (provider, source_url, observed_at);

CREATE TABLE IF NOT EXISTS doc_chunks (
  id String, provider LowCardinality(String), change_id String,
  source_url String, published_at DateTime,
  affected_package String, affected_version String,
  symbols Array(String), content String,
  embedding Array(Float32), embedding_model String
) ENGINE = MergeTree ORDER BY (provider, affected_package, id);

CREATE TABLE IF NOT EXISTS code_symbols (
  repo String, commit_sha String, path String,
  start_line UInt32, end_line UInt32,
  language LowCardinality(String), package String,
  symbol String, usage_context String,
  embedding Array(Float32), embedding_model String
) ENGINE = MergeTree ORDER BY (repo, commit_sha, package, path, start_line);

CREATE TABLE IF NOT EXISTS findings (
  observed_at DateTime64(3), finding_id String,
  repo String, commit_sha String, change_id String,
  finding_type LowCardinality(String), path String, line UInt32,
  status LowCardinality(String), confidence_tier LowCardinality(String),
  source_url String, model_score Float32, semgrep_rule String,
  test_status LowCardinality(String), pr_url String
) ENGINE = MergeTree ORDER BY (repo, observed_at, finding_id);

CREATE TABLE IF NOT EXISTS run_events (
  event_at DateTime64(3), run_id String,
  stage LowCardinality(String), provider LowCardinality(String),
  duration_ms UInt32, result LowCardinality(String),
  details String
) ENGINE = MergeTree ORDER BY (run_id, event_at);

-- Extension (not in the blueprint minimum): the full evidence document for each finding, so the UI can
-- render citations/tests without recomputation. findings above remains the analytic table.
CREATE TABLE IF NOT EXISTS finding_evidence (
  observed_at DateTime64(3), finding_id String, run_id String, evidence String
) ENGINE = ReplacingMergeTree(observed_at) ORDER BY finding_id;

CREATE TABLE IF NOT EXISTS query_latency (
  measured_at DateTime64(3), query_name LowCardinality(String),
  elapsed_ms Float64, rows_read UInt64, bytes_read UInt64, result_rows UInt32, run_id String
) ENGINE = MergeTree ORDER BY (query_name, measured_at);

CREATE TABLE IF NOT EXISTS investigations (
  started_at DateTime64(3), run_id String, repo String, branch String, commit_sha String,
  status LowCardinality(String), summary String
) ENGINE = ReplacingMergeTree(started_at) ORDER BY run_id;
