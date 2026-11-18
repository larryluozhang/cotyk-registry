import os

# Online window: a bridge with no heartbeat for 90s is treated as offline.
ONLINE_WINDOW_SECONDS = 90

# Heartbeat timestamp freshness: reject replays older/newer than this.
HEARTBEAT_TS_TOLERANCE_SECONDS = 60

DEFAULT_DB_PATH = "registry.db"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9400

# Rate limits (requests per 60s sliding window, per client IP).
RATE_LIMIT_GENERAL = 120
RATE_LIMIT_REGISTER = 30
RATE_WINDOW_SECONDS = 60


def env(name, default=None):
    return os.environ.get(name, default)


def owner_token():
    """Bearer token for DELETE (Owner credential). Unset disables deletion."""
    return env("REGISTRY_OWNER_TOKEN")


def realm_member_token():
    """Optional bearer token required for directory GET when configured."""
    return env("REGISTRY_MEMBER_TOKEN")
