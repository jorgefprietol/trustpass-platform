import json
import sys
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from trustpass.app import create_app  # noqa: E402
from trustpass.config import Settings  # noqa: E402

with TemporaryDirectory() as temporary:
    directory = Path(temporary)
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
    settings = Settings(
        role="issuer",
        database=str(directory / "db"),
        api_token="a" * 48,
        internal_token="b" * 48,
        private_key=str(private),
        public_key=str(public),
        run_worker=False,
    )
    (root / "contracts").mkdir(exist_ok=True)
    for role in ("issuer", "verifier", "audit"):
        schema = create_app(replace(settings, role=role)).openapi()
        (root / "contracts" / f"{role}.json").write_text(
            json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
print("OpenAPI contracts exported.")
