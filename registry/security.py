"""Signature verification, canonical signing strings, rate limiting.

Trust model: the registry is NOT a trust root. It only checks that
register/heartbeat payloads are signed by the Ed25519 key the bridge
itself reports. Clients pin bridge public keys at first pairing, so a
compromised registry cannot redirect them.
"""
import json
import threading
import time
from collections import deque

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

import registry.config as cfg


def canonical_capabilities(capabilities):
    return json.dumps(capabilities, sort_keys=True, separators=(",", ":"))


def register_signing_bytes(realm_id, bridge_id, host_name, endpoint, public_key, capabilities):
    parts = [
        "cotyk-reg-v1", realm_id, bridge_id, host_name,
        endpoint, public_key, canonical_capabilities(capabilities),
    ]
    return "|".join(parts).encode("utf-8")


def heartbeat_signing_bytes(bridge_id, status, ts):
    return "|".join(["cotyk-hb-v1", bridge_id, status, str(ts)]).encode("utf-8")


def verify_signature(public_key_hex, signing_bytes, signature_hex):
    """Verify an Ed25519 signature. Returns True/False (never raises)."""
    try:
        key = bytes.fromhex(public_key_hex)
        sig = bytes.fromhex(signature_hex)
        if len(key) != 32 or len(sig) != 64:
            return False
        VerifyKey(key).verify(signing_bytes, sig)
        return True
    except (ValueError, BadSignatureError):
        return False


def validate_endpoint(url):
    """Cheap format validation only. The registry never fetches this URL."""
    if not isinstance(url, str) or not (1 <= len(url) <= 512):
        return False
    if "://" not in url:
        return False
    scheme, rest = url.split("://", 1)
    if scheme not in ("http", "https"):
        return False
    if "@" in rest.split("/", 1)[0]:  # no userinfo
        return False
    host = rest.split("/", 1)[0].split(":", 1)[0]
    return bool(host)


class RateLimiter:
    """In-memory sliding-window limiter, keyed by (scope, client_ip)."""

    def __init__(self, window_seconds=cfg.RATE_WINDOW_SECONDS):
        self._window = window_seconds
        self._events = {}
        self._lock = threading.Lock()

    def allow(self, scope, key, limit):
        now = time.monotonic()
        bucket = (scope, key)
        with self._lock:
            q = self._events.setdefault(bucket, deque())
            while q and q[0] <= now - self._window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


def check_heartbeat_ts(ts):
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return False
    return abs(int(time.time()) - ts) <= cfg.HEARTBEAT_TS_TOLERANCE_SECONDS
