import json
from uuid import uuid4

import httpx

from trustpass.worker import deliver_once


def event():
    return {
        "id": str(uuid4()),
        "credential_id": str(uuid4()),
        "event_type": "credential.issued",
        "occurred_at": 1700000000,
        "request_id": "request-audit",
    }


def test_audit_inbox_deduplicates_and_rejects_collisions(audit, settings, headers):
    internal = {"Authorization": f"Bearer {settings.internal_token}"}
    payload = event()
    assert audit.post("/internal/events", json=payload, headers=headers).status_code == 401
    assert (
        audit.post("/internal/events", json=payload, headers=internal).json()["duplicate"] is False
    )
    assert (
        audit.post("/internal/events", json=payload, headers=internal).json()["duplicate"] is True
    )
    assert (
        audit.post(
            "/internal/events",
            json={**payload, "event_type": "credential.revoked"},
            headers=internal,
        ).status_code
        == 409
    )
    assert len(audit.get("/api/v1/events", headers=headers).json()) == 1


def test_outbox_retries_and_drains_without_duplicate_events(
    client, audit, body, headers, settings, monkeypatch
):
    import asyncio

    client.post("/api/v1/credentials", json=body, headers=headers)
    original = httpx.AsyncClient
    offline = True

    def handle(request):
        if offline:
            return httpx.Response(503)
        response = audit.post(
            "/internal/events",
            json=json.loads(request.content),
            headers={"Authorization": request.headers["Authorization"]},
        )
        return httpx.Response(response.status_code, json=response.json())

    monkeypatch.setattr(
        "trustpass.worker.httpx.AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs),
    )
    asyncio.run(deliver_once(client.app.state.store, settings))
    with client.app.state.store.connect() as db:
        row = db.execute("SELECT delivered,attempts FROM outbox").fetchone()
        assert tuple(row) == (0, 1)
    offline = False
    asyncio.run(deliver_once(client.app.state.store, settings))
    asyncio.run(deliver_once(client.app.state.store, settings))
    assert len(audit.get("/api/v1/events", headers=headers).json()) == 1
    with client.app.state.store.connect() as db:
        assert db.execute("SELECT delivered FROM outbox").fetchone()[0] == 1
