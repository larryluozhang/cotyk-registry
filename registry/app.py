import secrets
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, constr

import registry.config as cfg
from registry.db import Database
from registry.security import (
    RateLimiter,
    check_heartbeat_ts,
    heartbeat_signing_bytes,
    register_signing_bytes,
    validate_endpoint,
    verify_signature,
)


class RegisterRequest(BaseModel):
    realm_id: constr(min_length=1, max_length=128)
    bridge_id: constr(min_length=1, max_length=128)
    host_name: constr(min_length=1, max_length=255)
    endpoint: constr(min_length=1, max_length=512)
    public_key: constr(min_length=64, max_length=66)
    capabilities: dict = Field(default_factory=dict)
    signature: constr(min_length=128, max_length=132)


class HeartbeatRequest(BaseModel):
    bridge_id: constr(min_length=1, max_length=128)
    status: constr(min_length=1, max_length=32)
    ts: int
    signature: constr(min_length=128, max_length=132)


def _client_ip(request):
    return request.client.host if request.client else "unknown"


def _auth_bearer(authorization, expected):
    if not expected:
        return False
    if not authorization or not authorization.startswith("Bearer "):
        return False
    return secrets.compare_digest(authorization[7:], expected)


def create_app(db_path=None):
    app = FastAPI(title="COTYK Bridge Registry", version="0.1.0")
    db = Database(db_path or cfg.env("REGISTRY_DB_PATH", cfg.DEFAULT_DB_PATH))
    limiter = RateLimiter()
    app.state.db = db
    owner_token = cfg.owner_token()
    member_token = cfg.realm_member_token()

    def guard(request, scope, limit):
        if not limiter.allow(scope, _client_ip(request), limit):
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok", "time": int(time.time())}

    @app.post("/api/v1/bridges/register")
    def register(body: RegisterRequest, request: Request):
        guard(request, "register", cfg.RATE_LIMIT_REGISTER)
        if not validate_endpoint(body.endpoint):
            raise HTTPException(status_code=400, detail="invalid endpoint")
        signing = register_signing_bytes(
            body.realm_id, body.bridge_id, body.host_name,
            body.endpoint, body.public_key, body.capabilities,
        )
        if not verify_signature(body.public_key, signing, body.signature):
            raise HTTPException(status_code=401, detail="invalid signature")
        seq = db.register(body.dict())
        return {"ok": True, "registration_seq": seq}

    @app.post("/api/v1/bridges/heartbeat")
    def heartbeat(body: HeartbeatRequest, request: Request):
        guard(request, "heartbeat", cfg.RATE_LIMIT_GENERAL)
        record = db.get(body.bridge_id)
        if not record:
            raise HTTPException(status_code=404, detail="unknown bridge")
        if not check_heartbeat_ts(body.ts):
            raise HTTPException(status_code=401, detail="stale timestamp")
        signing = heartbeat_signing_bytes(body.bridge_id, body.status, body.ts)
        if not verify_signature(record["public_key"], signing, body.signature):
            raise HTTPException(status_code=401, detail="invalid signature")
        if not db.heartbeat(body.bridge_id, body.status):
            raise HTTPException(status_code=404, detail="unknown bridge")
        return {"ok": True}

    @app.get("/api/v1/realms/{realm_id}/bridges")
    def realm_bridges(realm_id: str, request: Request,
                      authorization: str = Header(default=None)):
        guard(request, "directory", cfg.RATE_LIMIT_GENERAL)
        if member_token and not _auth_bearer(authorization, member_token):
            raise HTTPException(status_code=401, detail="member credential required")
        now = int(time.time())
        bridges = []
        for row in db.list_by_realm(realm_id):
            online = (now - row["last_seen"]) <= cfg.ONLINE_WINDOW_SECONDS
            bridges.append({
                "bridge_id": row["bridge_id"],
                "host_name": row["host_name"],
                "endpoint": row["endpoint"],
                "public_key": row["public_key"],
                "capabilities": row["capabilities"],
                "status": "online" if online else "offline",
                "last_seen": row["last_seen"],
                "registration_seq": row["registration_seq"],
            })
        return {"realm_id": realm_id, "bridges": bridges}

    @app.delete("/api/v1/bridges/{bridge_id}")
    def delete_bridge(bridge_id: str, request: Request,
                      authorization: str = Header(default=None)):
        guard(request, "delete", cfg.RATE_LIMIT_GENERAL)
        if not _auth_bearer(authorization, owner_token):
            raise HTTPException(status_code=401, detail="owner credential required")
        if not db.delete(bridge_id):
            raise HTTPException(status_code=404, detail="unknown bridge")
        return {"ok": True}

    return app
