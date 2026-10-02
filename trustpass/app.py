import asyncio
import hashlib
import hmac
import json
import logging
import re
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID, uuid4

import httpx
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest
from pydantic import BaseModel, ConfigDict, Field

from trustpass.config import Settings
from trustpass.keyring import jwks as public_jwks
from trustpass.keyring import trusted_keys
from trustpass.store import Store
from trustpass.worker import run_worker

logger = logging.getLogger("trustpass")
bearer = HTTPBearer(auto_error=False)
Auth = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


class IssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$")
    category: Literal["facility-access", "professional-certification", "event-pass"]
    valid_for_seconds: int = Field(default=86400, ge=60, le=2592000)


class Credential(BaseModel):
    id: UUID
    subject: str
    category: str
    status: Literal["active", "revoked"]
    expires_at: int
    token: str


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=40, max_length=8192)


class Verification(BaseModel):
    valid: bool
    reason: Literal["active", "expired", "invalid_signature", "revoked", "unknown"]
    credential_id: str | None = None


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: UUID
    credential_id: UUID
    event_type: Literal["credential.issued", "credential.revoked"]
    occurred_at: int = Field(ge=0)
    request_id: str = Field(max_length=64)


def create_app(settings: Settings | None = None):
    settings = settings or Settings.from_env()
    if not 1 <= settings.max_delivery_attempts <= 50:
        raise ValueError("Delivery attempts must be between 1 and 50")
    if min(len(settings.api_token), len(settings.internal_token)) < 32:
        raise ValueError("Tokens must contain at least 32 characters")
    store = Store(settings.database)
    private_key = Path(settings.private_key).read_bytes() if settings.role == "issuer" else None
    if settings.role in {"issuer", "verifier"}:
        trusted_keys(settings)
    registry = CollectorRegistry()
    requests = Counter(
        "trustpass_http_requests", "HTTP requests", ["role", "route", "status"], registry=registry
    )
    duration = Histogram(
        "trustpass_http_duration_seconds", "HTTP duration", ["role", "route"], registry=registry
    )

    @asynccontextmanager
    async def lifespan(app):
        store.initialize(settings.role)
        worker = (
            asyncio.create_task(run_worker(store, settings))
            if settings.role == "issuer" and settings.run_worker
            else None
        )
        yield
        if worker:
            worker.cancel()
            with suppress(asyncio.CancelledError):
                await worker

    app = FastAPI(
        title=f"TrustPass {settings.role.title()} API", version="1.0.0", lifespan=lifespan
    )
    app.state.store = store

    def authorize(auth, expected):
        if auth is None or not hmac.compare_digest(auth.credentials.encode(), expected.encode()):
            raise HTTPException(401, "Invalid credentials", headers={"WWW-Authenticate": "Bearer"})

    def external_auth(auth: Auth):
        authorize(auth, settings.api_token)

    def internal_auth(auth: Auth):
        authorize(auth, settings.internal_token)

    @app.middleware("http")
    async def observability(request: Request, call_next):
        supplied = request.headers.get("X-Request-ID", "")
        request.state.request_id = (
            supplied if re.fullmatch(r"[a-zA-Z0-9-]{1,64}", supplied) else str(uuid4())
        )
        start = time.perf_counter()
        response = await call_next(request)
        route = getattr(request.scope.get("route"), "path", "unmatched")
        requests.labels(settings.role, route, response.status_code).inc()
        duration.labels(settings.role, route).observe(time.perf_counter() - start)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        if route not in {"/health/live", "/health/ready", "/metrics"}:
            logger.info(
                json.dumps(
                    {
                        "role": settings.role,
                        "request_id": request.state.request_id,
                        "route": route,
                        "status": response.status_code,
                    }
                )
            )
        return response

    @app.get("/health/live")
    def live():
        return {"status": "ok", "role": settings.role}

    @app.get("/health/ready")
    def ready():
        with store.connect() as db:
            db.execute("SELECT 1")
        return {"status": "ready", "role": settings.role}

    @app.get("/metrics", dependencies=[Depends(internal_auth)], include_in_schema=False)
    def metrics():
        return Response(generate_latest(registry), media_type="text/plain; version=0.0.4")

    if settings.role == "issuer":

        @app.get("/.well-known/jwks.json")
        def jwks():
            return public_jwks(settings)

        @app.post(
            "/api/v1/credentials",
            response_model=Credential,
            status_code=201,
            dependencies=[Depends(external_auth)],
        )
        def issue(
            body: IssueRequest,
            request: Request,
            response: Response,
            idempotency_key: Annotated[str, Header(min_length=8, max_length=128)],
        ):
            fingerprint = hashlib.sha256(body.model_dump_json().encode()).hexdigest()
            with store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute(
                    "SELECT * FROM requests WHERE key=?", (idempotency_key,)
                ).fetchone()
                if existing:
                    if existing["fingerprint"] != fingerprint:
                        raise HTTPException(409, "Idempotency key already used for another request")
                    response.headers["Idempotency-Replayed"] = "true"
                    return json.loads(existing["response"])
                now = int(time.time())
                credential_id = str(uuid4())
                expires = now + body.valid_for_seconds
                token = jwt.encode(
                    {
                        "iss": settings.issuer,
                        "aud": settings.audience,
                        "sub": body.subject,
                        "jti": credential_id,
                        "iat": now,
                        "nbf": now,
                        "exp": expires,
                        "category": body.category,
                    },
                    private_key,
                    algorithm="RS256",
                    headers={"kid": settings.key_id, "typ": "JWT"},
                )
                result = {
                    "id": credential_id,
                    "subject": body.subject,
                    "category": body.category,
                    "status": "active",
                    "expires_at": expires,
                    "token": token,
                }
                db.execute(
                    "INSERT INTO credentials VALUES (?,?,?,?,?,?,?,?)",
                    (
                        credential_id,
                        body.subject,
                        body.category,
                        expires,
                        "active",
                        token,
                        now,
                        None,
                    ),
                )
                db.execute(
                    "INSERT INTO requests VALUES (?,?,?)",
                    (idempotency_key, fingerprint, json.dumps(result)),
                )
                store.enqueue(
                    db,
                    {
                        "id": str(uuid4()),
                        "credential_id": credential_id,
                        "event_type": "credential.issued",
                        "occurred_at": now,
                        "request_id": request.state.request_id,
                    },
                )
                return result

        @app.get("/api/v1/credentials", dependencies=[Depends(external_auth)])
        def list_credentials():
            with store.connect() as db:
                return [
                    dict(row)
                    for row in db.execute(
                        "SELECT id,subject,category,status,expires_at,created_at "
                        "FROM credentials ORDER BY created_at DESC LIMIT 100"
                    )
                ]

        @app.post(
            "/api/v1/credentials/{credential_id}/revoke", dependencies=[Depends(external_auth)]
        )
        def revoke(credential_id: UUID, request: Request):
            with store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT status FROM credentials WHERE id=?", (str(credential_id),)
                ).fetchone()
                if not row:
                    raise HTTPException(404, "Credential not found")
                if row["status"] == "active":
                    now = int(time.time())
                    db.execute(
                        "UPDATE credentials SET status='revoked', revoked_at=? WHERE id=?",
                        (now, str(credential_id)),
                    )
                    store.enqueue(
                        db,
                        {
                            "id": str(uuid4()),
                            "credential_id": str(credential_id),
                            "event_type": "credential.revoked",
                            "occurred_at": now,
                            "request_id": request.state.request_id,
                        },
                    )
                return {"id": str(credential_id), "status": "revoked"}

        @app.get(
            "/internal/credentials/{credential_id}/status", dependencies=[Depends(internal_auth)]
        )
        def credential_status(credential_id: UUID):
            with store.connect() as db:
                row = db.execute(
                    "SELECT status FROM credentials WHERE id=?", (str(credential_id),)
                ).fetchone()
                if not row:
                    raise HTTPException(404, "Credential not found")
                return {"status": row["status"]}

        @app.get("/internal/outbox", dependencies=[Depends(internal_auth)])
        def outbox_status():
            with store.connect() as db:
                count = db.execute(
                    "SELECT COUNT(*) FROM outbox WHERE delivered=0 AND dead_letter=0"
                ).fetchone()[0]
                dead = db.execute("SELECT COUNT(*) FROM outbox WHERE dead_letter=1").fetchone()[0]
                return {"pending": count, "dead_letter": dead}

        @app.post("/internal/outbox/{event_id}/retry", dependencies=[Depends(internal_auth)])
        def retry_dead_letter(event_id: UUID):
            with store.connect() as db:
                updated = db.execute(
                    "UPDATE outbox SET attempts=0,dead_letter=0,next_attempt_at=0,last_error=NULL "
                    "WHERE id=? AND delivered=0 AND dead_letter=1",
                    (str(event_id),),
                ).rowcount
                if not updated:
                    raise HTTPException(404, "Dead letter not found")
            return {"scheduled": True}

    if settings.role == "verifier":

        @app.post(
            "/api/v1/verifications",
            response_model=Verification,
            dependencies=[Depends(external_auth)],
        )
        async def verify(body: VerifyRequest, request: Request):
            try:
                key = trusted_keys(settings).get(jwt.get_unverified_header(body.token).get("kid"))
                if key is None:
                    raise jwt.InvalidTokenError("Untrusted key")
                claims = jwt.decode(
                    body.token,
                    key,
                    algorithms=["RS256"],
                    issuer=settings.issuer,
                    audience=settings.audience,
                    options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]},
                )
                credential_id = str(UUID(claims["jti"]))
            except jwt.ExpiredSignatureError:
                return {"valid": False, "reason": "expired"}
            except (jwt.InvalidTokenError, ValueError, TypeError, KeyError):
                return {"valid": False, "reason": "invalid_signature"}
            try:
                async with httpx.AsyncClient(timeout=3) as client:
                    result = await client.get(
                        f"{settings.issuer_url}/internal/credentials/{credential_id}/status",
                        headers={
                            "Authorization": f"Bearer {settings.internal_token}",
                            "X-Request-ID": request.state.request_id,
                        },
                    )
                    if result.status_code == 404:
                        return {"valid": False, "reason": "unknown", "credential_id": credential_id}
                    result.raise_for_status()
                    status = result.json()["status"]
                    if status not in {"active", "revoked"}:
                        raise ValueError("Invalid status")
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                raise HTTPException(
                    503, "Revocation registry unavailable; verification denied"
                ) from None
            return {"valid": status == "active", "reason": status, "credential_id": credential_id}

    if settings.role == "audit":

        @app.post("/internal/events", dependencies=[Depends(internal_auth)])
        def ingest(event: Event):
            with store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                values = (
                    str(event.id),
                    str(event.credential_id),
                    event.event_type,
                    event.occurred_at,
                    event.request_id,
                )
                existing = db.execute(
                    "SELECT * FROM events WHERE id=?", (str(event.id),)
                ).fetchone()
                if existing and tuple(existing) != values:
                    raise HTTPException(409, "Event ID collision")
                db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?)", values)
            return {"accepted": True, "duplicate": existing is not None}

        @app.get("/api/v1/events", dependencies=[Depends(external_auth)])
        def events():
            with store.connect() as db:
                return [
                    dict(row)
                    for row in db.execute(
                        "SELECT * FROM events ORDER BY occurred_at DESC, rowid DESC LIMIT 100"
                    )
                ]

    return app
