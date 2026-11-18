#!/usr/bin/env python3
"""G0 self-test for the COTYK Bridge Registry.

Runs entirely in-process against the ASGI app (no network sockets).
Exit code 0 = all checks pass. Uses a temp SQLite DB.
"""
import json
import os
import sys
import tempfile
import time

from fastapi.testclient import TestClient
from nacl.signing import SigningKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from registry.app import create_app  # noqa: E402
import registry.config as cfg  # noqa: E402
from registry.security import (  # noqa: E402
    heartbeat_signing_bytes,
    register_signing_bytes,
)

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + ((" — " + detail) if detail else ""))


def main():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    os.unlink(tmp.name)

    os.environ["REGISTRY_OWNER_TOKEN"] = "owner-secret-token"
    os.environ["REGISTRY_MEMBER_TOKEN"] = "member-secret-token"
    try:
        app = create_app(tmp.name)
    finally:
        del os.environ["REGISTRY_OWNER_TOKEN"]
        del os.environ["REGISTRY_MEMBER_TOKEN"]

    client = TestClient(app, base_url="http://registry.test")

    sk = SigningKey.generate()
    pk_hex = sk.verify_key.encode().hex()
    other_sk = SigningKey.generate()
    realm = "realm-test-1"
    bridge = "bridge-abc"
    endpoint = "https://bridge-abc.lan.example:9443"
    caps = {"protocols": ["http", "ws"], "version": "1.0"}

    def reg_body(signing_key=sk, public_key=pk_hex, **overrides):
        body = {
            "realm_id": realm, "bridge_id": bridge,
            "host_name": "bridge-abc-host", "endpoint": endpoint,
            "public_key": public_key, "capabilities": caps,
        }
        body.update(overrides)
        signing = register_signing_bytes(
            body["realm_id"], body["bridge_id"], body["host_name"],
            body["endpoint"], body["public_key"], body["capabilities"],
        )
        body["signature"] = signing_key.sign(signing).signature.hex()
        return body

    # 1. health
    r = client.get("/api/v1/health")
    check("health endpoint", r.status_code == 200 and r.json()["status"] == "ok")

    # 2. register with valid signature
    r = client.post("/api/v1/bridges/register", json=reg_body())
    check("register with valid signature", r.status_code == 200
          and r.json().get("registration_seq") == 1, r.text if r.status_code != 200 else "")

    # 3. re-register increments registration_seq
    r = client.post("/api/v1/bridges/register", json=reg_body())
    check("registration_seq monotonic", r.status_code == 200
          and r.json().get("registration_seq") == 2)

    # 4. wrong signature rejected
    r = client.post("/api/v1/bridges/register", json=reg_body(signing_key=other_sk))
    check("register rejects bad signature", r.status_code == 401)

    # 5. signature/public_key mismatch rejected
    r = client.post("/api/v1/bridges/register",
                    json=reg_body(public_key=other_sk.verify_key.encode().hex()))
    check("register rejects key/signature mismatch", r.status_code == 401)

    # 6. invalid endpoint scheme rejected
    r = client.post("/api/v1/bridges/register",
                    json=reg_body(endpoint="ftp://x.example"))
    check("register rejects non-http endpoint", r.status_code == 400)

    # 7. directory: offline right away? last_seen just now → online
    r = client.get(f"/api/v1/realms/{realm}/bridges",
                   headers={"Authorization": "Bearer member-secret-token"})
    ok = False
    if r.status_code == 200:
        bridges = r.json()["bridges"]
        ok = len(bridges) == 1 and bridges[0]["status"] == "online" \
            and bridges[0]["public_key"] == pk_hex
    check("directory lists online bridge with pinned key", ok, r.text)

    # 8. directory requires member credential when configured
    r = client.get(f"/api/v1/realms/{realm}/bridges")
    check("directory GET requires member credential", r.status_code == 401)

    # 9. other realm is empty
    r = client.get("/api/v1/realms/other-realm/bridges",
                   headers={"Authorization": "Bearer member-secret-token"})
    check("directory scoped to realm", r.status_code == 200
          and r.json()["bridges"] == [])

    # 10. heartbeat with valid signature keeps online
    ts = int(time.time())
    sig = sk.sign(heartbeat_signing_bytes(bridge, "online", ts)).signature.hex()
    r = client.post("/api/v1/bridges/heartbeat",
                    json={"bridge_id": bridge, "status": "online", "ts": ts,
                          "signature": sig})
    check("heartbeat valid signature", r.status_code == 200, r.text)

    # 11. heartbeat bad signature rejected
    r = client.post("/api/v1/bridges/heartbeat",
                    json={"bridge_id": bridge, "status": "online", "ts": ts,
                          "signature": other_sk.sign(b"x").signature.hex()})
    check("heartbeat rejects bad signature", r.status_code == 401)

    # 12. stale timestamp rejected
    old_ts = ts - 600
    sig = sk.sign(heartbeat_signing_bytes(bridge, "online", old_ts)).signature.hex()
    r = client.post("/api/v1/bridges/heartbeat",
                    json={"bridge_id": bridge, "status": "online", "ts": old_ts,
                          "signature": sig})
    check("heartbeat rejects stale timestamp", r.status_code == 401)

    # 13. unknown bridge heartbeat → 404
    r = client.post("/api/v1/bridges/heartbeat",
                    json={"bridge_id": "nope", "status": "online", "ts": ts,
                          "signature": sig})
    check("heartbeat unknown bridge 404", r.status_code == 404)

    # 14. stale last_seen shows offline (backdate the DB directly)
    db = app.state.db
    with db._lock:
        db._conn.execute("UPDATE bridges SET last_seen = ? WHERE bridge_id = ?",
                         (int(time.time()) - cfg.ONLINE_WINDOW_SECONDS - 5, bridge))
        db._conn.commit()
    r = client.get(f"/api/v1/realms/{realm}/bridges",
                   headers={"Authorization": "Bearer member-secret-token"})
    ok = r.status_code == 200 and r.json()["bridges"][0]["status"] == "offline"
    check("no heartbeat >90s marked offline", ok)

    # 15. DELETE requires owner credential
    r = client.delete(f"/api/v1/bridges/{bridge}")
    check("DELETE without owner token 401", r.status_code == 401)
    r = client.delete(f"/api/v1/bridges/{bridge}",
                      headers={"Authorization": "Bearer wrong"})
    check("DELETE wrong owner token 401", r.status_code == 401)
    r = client.delete(f"/api/v1/bridges/{bridge}",
                      headers={"Authorization": "Bearer owner-secret-token"})
    check("DELETE with owner token removes bridge", r.status_code == 200)
    r = client.get(f"/api/v1/realms/{realm}/bridges",
                   headers={"Authorization": "Bearer member-secret-token"})
    check("deleted bridge gone from directory", r.json()["bridges"] == [])

    # 16. rate limit triggers
    client2 = TestClient(app, base_url="http://registry.test")
    limited = False
    for _ in range(cfg.RATE_LIMIT_REGISTER + 5):
        r = client2.post("/api/v1/bridges/register", json=reg_body())
        if r.status_code == 429:
            limited = True
            break
    check("register rate limited", limited)

    # 17. registry never makes outbound HTTP calls (static assertion)
    src_root = os.path.join(os.path.dirname(__file__), "..", "registry")
    bad = []
    for fn in os.listdir(src_root):
        if fn.endswith(".py"):
            with open(os.path.join(src_root, fn)) as f:
                text = f.read()
            for token in ("requests.", "urllib.request", "httpx.get", "httpx.post",
                          "aiohttp", "urlopen"):
                if token in text:
                    bad.append(f"{fn}:{token}")
    check("no outbound HTTP client usage in registry code", not bad, ",".join(bad))

    client.close()
    client2.close()
    os.unlink(tmp.name)

    failed = [n for n, ok in CHECKS if not ok]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("FAILED: " + ", ".join(failed))
        sys.exit(1)
    print("G0 self-test: ALL PASS")


if __name__ == "__main__":
    main()
