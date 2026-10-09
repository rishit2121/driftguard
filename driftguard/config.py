import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path, prefixes=("DRIFTGUARD_", "GUILD_", "ML_SERVICE_", "CLICKHOUSE_")):
    """Load only DriftGuard settings from .env (other secrets in that file are never read into the process)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key.startswith(prefixes) and key not in os.environ:
            os.environ[key] = value.strip().strip('"')


_load_dotenv(ROOT / ".env")
DATA_DIR = ROOT / "data"
SNAPSHOT_DIR = DATA_DIR / "snapshots"
WORK_DIR = Path(os.environ.get("DRIFTGUARD_WORKDIR", ROOT / ".work"))
RULES_DIR = ROOT / "semgrep-rules"
SCHEMA_PATH = ROOT / "clickhouse" / "schema.sql"

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_SECURE = os.environ.get("CLICKHOUSE_SECURE", "0") == "1"
CLICKHOUSE_DATABASE = os.environ.get("CLICKHOUSE_DATABASE", "driftguard")

# Akash-hosted inference service. Falls back to a local instance of the same container contract;
# the UI labels which one answered (health.deployment).
ML_SERVICE_URL = os.environ.get("ML_SERVICE_URL", "http://localhost:8100").rstrip("/")
ML_SERVICE_TOKEN = os.environ.get("ML_SERVICE_TOKEN", "")

DEMO_REPO = os.environ.get("DRIFTGUARD_REPO", "rishit2121/driftguard-demo-monorepo")
DEMO_BRANCH = os.environ.get("DRIFTGUARD_BRANCH", "main")

# "guild" = Guild remediation agent opens the PR through Guild's GitHub integration.
# "github" = disclosed fallback: platform opens the PR with the operator's own GitHub token.
PR_EXECUTOR = os.environ.get("DRIFTGUARD_PR_EXECUTOR", "github")
GUILD_REMEDIATOR_AGENT = os.environ.get("GUILD_REMEDIATOR_AGENT", "")
GUILD_WATCHER_AGENT = os.environ.get("GUILD_WATCHER_AGENT", "")

SEMGREP_BIN = os.environ.get("SEMGREP_BIN", str(Path.home() / ".local/bin/semgrep"))
PYTHON_TEST_VERSION = os.environ.get("DRIFTGUARD_PY_TEST_VERSION", "3.10")

# Watched sources. Only these hosts may be fetched (SSRF allowlist).
ALLOWED_SOURCE_HOSTS = {
    "docs.stripe.com",
    "api.osv.dev",
    "osv.dev",
    "shopify.dev",
    "unpkg.com",
    "registry.npmjs.org",
    "pypi.org",
    "repo1.maven.org",
}
STRIPE_CHANGELOG_URLS = [
    "https://docs.stripe.com/changelog/basil/2025-03-31/deprecate-subscription-current-period-start-and-end",
]
SHOPIFY_FEED_URL = "https://shopify.dev/changelog/feed.xml"
SHOPIFY_FEED_LIMIT = int(os.environ.get("SHOPIFY_FEED_LIMIT", "40"))
OSV_API = "https://api.osv.dev/v1"
