import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    role: str
    database: str
    api_token: str
    internal_token: str
    issuer_url: str = "http://issuer:8000"
    audit_url: str = "http://audit:8000"
    private_key: str = "/run/secrets/signing_key"
    public_key: str = "/run/secrets/verification_key"
    issuer: str = "https://trustpass.local"
    audience: str = "trustpass-verifier"
    key_id: str = "trustpass-2026-01"
    run_worker: bool = True
    trusted_keys_dir: str = ""
    max_delivery_attempts: int = 8

    @classmethod
    def from_env(cls):
        role = os.environ["SERVICE_ROLE"]
        if role not in {"issuer", "verifier", "audit"}:
            raise ValueError("Unsupported service role")
        return cls(
            role=role,
            database=os.getenv("DATABASE_PATH", "/data/service.db"),
            api_token=Path(os.environ["API_TOKEN_FILE"]).read_text().strip(),
            internal_token=Path(os.environ["INTERNAL_TOKEN_FILE"]).read_text().strip(),
            issuer_url=os.getenv("ISSUER_URL", "http://issuer:8000"),
            audit_url=os.getenv("AUDIT_URL", "http://audit:8000"),
            key_id=os.getenv("SIGNING_KEY_ID", "trustpass-2026-01"),
            trusted_keys_dir=os.getenv("TRUSTED_KEYS_DIR", ""),
            max_delivery_attempts=int(os.getenv("MAX_DELIVERY_ATTEMPTS", "8")),
        )
