import concurrent.futures
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient

from trustpass.app import create_app


def test_issue_signed_credential_with_atomic_event(client, body, headers, settings):
    response = client.post("/api/v1/credentials", json=body, headers=headers)
    assert response.status_code == 201
    result = response.json()
    public = Path(settings.public_key).read_bytes()
    claims = jwt.decode(
        result["token"],
        public,
        algorithms=["RS256"],
        audience=settings.audience,
        issuer=settings.issuer,
    )
    assert claims["sub"] == body["subject"]
    assert claims["jti"] == result["id"]
    assert jwt.get_unverified_header(result["token"])["kid"] == settings.key_id
    with client.app.state.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1
    listing = client.get("/api/v1/credentials", headers=headers).json()
    assert listing[0]["id"] == result["id"]
    assert "token" not in listing[0]


def test_idempotency_persists_across_restart(client, settings, body, headers):
    issued = client.post("/api/v1/credentials", json=body, headers=headers).json()
    with TestClient(create_app(settings)) as restarted:
        replay = restarted.post("/api/v1/credentials", json=body, headers=headers)
    assert replay.json() == issued
    assert replay.headers["Idempotency-Replayed"] == "true"
    conflict = client.post(
        "/api/v1/credentials", json={**body, "subject": "member-002"}, headers=headers
    )
    assert conflict.status_code == 409


def test_parallel_duplicates_create_one_credential(client, body, headers):
    def post(_):
        return client.post("/api/v1/credentials", json=body, headers=headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(post, range(12)))
    assert all(response.status_code == 201 for response in responses)
    assert len({response.json()["id"] for response in responses}) == 1
    with client.app.state.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1


def test_revoke_is_idempotent(client, body, headers, settings):
    issued = client.post("/api/v1/credentials", json=body, headers=headers).json()
    path = f"/api/v1/credentials/{issued['id']}/revoke"
    assert client.post(path, headers=headers).json()["status"] == "revoked"
    assert client.post(path, headers=headers).status_code == 200
    internal = {"Authorization": f"Bearer {settings.internal_token}"}
    assert (
        client.get(f"/internal/credentials/{issued['id']}/status", headers=internal).json()[
            "status"
        ]
        == "revoked"
    )
    assert client.get("/internal/outbox", headers=internal).json()["pending"] == 2
    assert client.post(f"/api/v1/credentials/{uuid4()}/revoke", headers=headers).status_code == 404
    assert (
        client.get(f"/internal/credentials/{uuid4()}/status", headers=internal).status_code == 404
    )


@pytest.mark.parametrize(
    "change",
    [
        {"subject": "<script>"},
        {"category": "unsupported"},
        {"valid_for_seconds": 0},
        {"valid_for_seconds": 2592001},
        {"extra": "unwanted"},
    ],
)
def test_invalid_input_rejected(client, body, headers, change):
    assert (
        client.post("/api/v1/credentials", json={**body, **change}, headers=headers).status_code
        == 422
    )


def test_auth_and_validation(client, body, headers, settings):
    for authorization in (None, "Bearer wrong", f"Bearer {settings.internal_token}"):
        request_headers = {} if authorization is None else {"Authorization": authorization}
        assert (
            client.post("/api/v1/credentials", json=body, headers=request_headers).status_code
            == 401
        )
    assert (
        client.post(
            "/api/v1/credentials", json=body, headers={"Authorization": headers["Authorization"]}
        ).status_code
        == 422
    )
    assert client.post("/api/v1/credentials/no-uuid/revoke", headers=headers).status_code == 422
    assert client.get("/internal/outbox", headers=headers).status_code == 401
    assert client.get("/metrics", headers=headers).status_code == 401
    metrics = client.get("/metrics", headers={"Authorization": f"Bearer {settings.internal_token}"})
    assert "trustpass_http_requests" in metrics.text


def test_jwks_health_and_request_correlation(client):
    assert client.get("/health/live").json()["status"] == "ok"
    assert client.get("/health/ready").status_code == 200
    response = client.get("/.well-known/jwks.json", headers={"X-Request-ID": "request-abc"})
    assert response.headers["X-Request-ID"] == "request-abc"
    key = response.json()["keys"][0]
    assert key["kty"] == "RSA" and key["alg"] == "RS256"
    assert "d" not in key
    assert (
        client.get("/health/live", headers={"X-Request-ID": "evil space"}).headers["X-Request-ID"]
        != "evil space"
    )


def test_short_tokens_fail_at_startup(settings):
    with pytest.raises(ValueError, match="32"):
        create_app(replace(settings, api_token="short"))


def test_database_transaction_rolls_back(client):
    with pytest.raises(RuntimeError), client.app.state.store.connect() as db:
        db.execute("INSERT INTO requests VALUES ('rollback','fingerprint','{}')")
        raise RuntimeError("failure")
    with client.app.state.store.connect() as db:
        assert db.execute("SELECT * FROM requests WHERE key='rollback'").fetchone() is None
