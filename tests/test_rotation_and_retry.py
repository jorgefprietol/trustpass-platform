import asyncio
import importlib.util
import sqlite3
import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from trustpass.app import create_app
from trustpass.store import Store
from trustpass.worker import deliver_once


def test_rotation_changes_signer_and_retains_previous_jwks(settings, keys, tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts" / "rotate-keys.py"
    spec = importlib.util.spec_from_file_location("rotate_keys", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    secrets = tmp_path / ".secrets"
    secrets.mkdir()
    (secrets / "signing.pem").write_bytes(Path(keys[0]).read_bytes())
    (secrets / "verification.pem").write_bytes(Path(keys[1]).read_bytes())
    (tmp_path / ".env").write_text(f"SIGNING_KEY_ID={settings.key_id}\n", encoding="utf-8")
    module.rotate(tmp_path, "rotated-key")
    assert (secrets / "keyring" / f"{settings.key_id}.pem").read_bytes() == Path(
        keys[1]
    ).read_bytes()
    assert (secrets / "verification.pem").read_bytes() != Path(keys[1]).read_bytes()
    rotated = replace(
        settings,
        key_id="rotated-key",
        private_key=str(secrets / "signing.pem"),
        public_key=str(secrets / "verification.pem"),
        trusted_keys_dir=str(secrets / "keyring"),
    )
    with TestClient(create_app(rotated)) as client:
        jwks = client.get("/.well-known/jwks.json").json()["keys"]
        assert {key["kid"] for key in jwks} == {settings.key_id, "rotated-key"}
        assert len({key["n"] for key in jwks}) == 2
    with pytest.raises(ValueError, match="fresh"):
        module.rotate(tmp_path, "rotated-key")


def test_migration_preserves_existing_pending_events(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE outbox (id TEXT PRIMARY KEY, payload TEXT, "
            "delivered INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0)"
        )
        db.execute("INSERT INTO outbox(id,payload) VALUES ('old-event','{}')")
    store = Store(str(path))
    store.initialize("issuer")
    store.initialize("issuer")
    with store.connect() as db:
        row = db.execute("SELECT * FROM outbox").fetchone()
        assert row["id"] == "old-event"
        assert row["next_attempt_at"] == 0
        assert row["dead_letter"] == 0


def test_previous_key_remains_trusted_and_unknown_key_is_rejected(
    settings, keys, headers, monkeypatch, tmp_path
):
    ring = tmp_path / "keyring"
    ring.mkdir()
    (ring / "old-key.pem").write_bytes(Path(keys[1]).read_bytes())
    original = httpx.AsyncClient
    monkeypatch.setattr(
        "trustpass.app.httpx.AsyncClient",
        lambda **kw: original(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"status": "active"})
            ),
            **kw,
        ),
    )
    now = int(time.time())
    claims = {
        "sub": "member-001",
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        "iss": settings.issuer,
        "aud": settings.audience,
    }
    with TestClient(
        create_app(replace(settings, role="verifier", trusted_keys_dir=str(ring)))
    ) as client:
        for kid, expected in (("old-key", True), ("untrusted", False)):
            token = jwt.encode(
                claims, Path(keys[0]).read_bytes(), algorithm="RS256", headers={"kid": kid}
            )
            assert (
                client.post("/api/v1/verifications", json={"token": token}, headers=headers).json()[
                    "valid"
                ]
                is expected
            )


def test_failed_delivery_obeys_backoff_then_dead_letters_and_can_be_requeued(
    client, settings, body, headers, monkeypatch
):
    client.post("/api/v1/credentials", json=body, headers=headers)
    original = httpx.AsyncClient
    monkeypatch.setattr(
        "trustpass.worker.httpx.AsyncClient",
        lambda **kw: original(
            transport=httpx.MockTransport(lambda request: httpx.Response(503)), **kw
        ),
    )
    config = replace(settings, max_delivery_attempts=2)
    store = client.app.state.store
    asyncio.run(deliver_once(store, config, now=100))
    asyncio.run(deliver_once(store, config, now=100))
    with store.connect() as db:
        assert db.execute("SELECT attempts FROM outbox").fetchone()[0] == 1
    asyncio.run(deliver_once(store, config, now=200))
    internal = {"Authorization": f"Bearer {settings.internal_token}"}
    assert client.get("/internal/outbox", headers=internal).json() == {
        "pending": 0,
        "dead_letter": 1,
    }
    with store.connect() as db:
        event_id = db.execute("SELECT id FROM outbox").fetchone()[0]
    assert client.post(f"/internal/outbox/{event_id}/retry", headers=internal).status_code == 200
    assert client.get("/internal/outbox", headers=internal).json() == {
        "pending": 1,
        "dead_letter": 0,
    }
