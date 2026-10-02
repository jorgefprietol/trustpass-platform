from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from trustpass.app import create_app
from trustpass.config import Settings


@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    directory = tmp_path_factory.mktemp("keys")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = directory / "private.pem"
    public = directory / "public.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public


@pytest.fixture
def settings(tmp_path, keys):
    return Settings(
        role="issuer",
        database=str(tmp_path / "issuer.db"),
        api_token="a" * 48,
        internal_token="b" * 48,
        private_key=str(keys[0]),
        public_key=str(keys[1]),
        run_worker=False,
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def audit(settings, tmp_path):
    config = replace(settings, role="audit", database=str(tmp_path / "audit.db"))
    with TestClient(create_app(config)) as test_client:
        yield test_client


@pytest.fixture
def headers(settings):
    return {"Authorization": f"Bearer {settings.api_token}", "Idempotency-Key": "test-request-001"}


@pytest.fixture
def body():
    return {"subject": "member-001", "category": "facility-access", "valid_for_seconds": 3600}
