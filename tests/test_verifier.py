import time
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from trustpass.app import create_app


def verifier(settings, monkeypatch, status=200, response=None, failure=False):
    original = httpx.AsyncClient

    def handle(request):
        assert request.headers["Authorization"] == f"Bearer {settings.internal_token}"
        if failure:
            raise httpx.ConnectError("offline", request=request)
        return httpx.Response(status, json={"status": "active"} if response is None else response)

    monkeypatch.setattr(
        "trustpass.app.httpx.AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs),
    )
    return TestClient(create_app(replace(settings, role="verifier")))


def signed(settings, **overrides):
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": "member-001",
        "jti": str(uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
        **overrides,
    }
    return jwt.encode(
        claims,
        Path(settings.private_key).read_bytes(),
        algorithm="RS256",
        headers={"kid": settings.key_id},
    )


@pytest.mark.parametrize("status,expected", [("active", True), ("revoked", False)])
def test_registry_status_checked(settings, headers, monkeypatch, status, expected):
    with verifier(settings, monkeypatch, response={"status": status}) as client:
        response = client.post(
            "/api/v1/verifications", json={"token": signed(settings)}, headers=headers
        )
    assert response.json()["valid"] is expected
    assert response.json()["reason"] == status


@pytest.mark.parametrize(
    "claims,reason",
    [
        ({"exp": 1}, "expired"),
        ({"aud": "other"}, "invalid_signature"),
        ({"iss": "other"}, "invalid_signature"),
        ({"jti": "invalid"}, "invalid_signature"),
        ({"nbf": 9999999999}, "invalid_signature"),
    ],
)
def test_invalid_claims_denied(settings, headers, monkeypatch, claims, reason):
    with verifier(settings, monkeypatch, failure=True) as client:
        response = client.post(
            "/api/v1/verifications", json={"token": signed(settings, **claims)}, headers=headers
        )
    assert response.json()["valid"] is False
    assert response.json()["reason"] == reason


@pytest.mark.parametrize("kind", ["tampered", "hmac", "unknown-key", "missing-claim", "malformed"])
def test_untrusted_tokens_denied(settings, headers, monkeypatch, kind):
    token = signed(settings)
    if kind == "tampered":
        parts = token.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        token = ".".join(parts)
    elif kind == "hmac":
        token = jwt.encode(
            {"sub": "member-001"},
            "attacker-secret" * 5,
            algorithm="HS256",
            headers={"kid": settings.key_id},
        )
    elif kind == "unknown-key":
        token = jwt.encode(
            {"sub": "member-001"},
            Path(settings.private_key).read_bytes(),
            algorithm="RS256",
            headers={"kid": "attacker"},
        )
    elif kind == "missing-claim":
        token = jwt.encode(
            {"sub": "member-001"},
            Path(settings.private_key).read_bytes(),
            algorithm="RS256",
            headers={"kid": settings.key_id},
        )
    else:
        token = "invalid-token" * 5
    with verifier(settings, monkeypatch, failure=True) as client:
        result = client.post("/api/v1/verifications", json={"token": token}, headers=headers).json()
    assert result["reason"] == "invalid_signature"


@pytest.mark.parametrize(
    "status,body,failure",
    [
        (500, {"status": "active"}, False),
        (200, {"status": "unexpected"}, False),
        (200, {"missing": True}, False),
        (200, [], False),
        (200, None, True),
    ],
)
def test_registry_failure_denies_verification(
    settings, headers, monkeypatch, status, body, failure
):
    with verifier(settings, monkeypatch, status=status, response=body, failure=failure) as client:
        assert (
            client.post(
                "/api/v1/verifications", json={"token": signed(settings)}, headers=headers
            ).status_code
            == 503
        )


def test_unknown_credential(settings, headers, monkeypatch):
    with verifier(settings, monkeypatch, status=404) as client:
        assert (
            client.post(
                "/api/v1/verifications", json={"token": signed(settings)}, headers=headers
            ).json()["reason"]
            == "unknown"
        )
