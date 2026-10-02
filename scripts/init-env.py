import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

root = Path(__file__).resolve().parents[1]
directory = root / ".secrets"
directory.mkdir(exist_ok=True)
private = directory / "signing.pem"
public = directory / "verification.pem"
if private.exists() != public.exists():
    raise SystemExit("Incomplete signing key pair. Restore the missing key before continuing.")
if not private.exists():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
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
for name in ("api-token", "internal-token"):
    path = directory / name
    if not path.exists():
        path.write_text(secrets.token_urlsafe(48), encoding="utf-8")
    if os.name != "nt":
        # Compose file secrets preserve host modes; the container runs as UID 10001.
        path.chmod(0o444)
if os.name != "nt":
    private.chmod(0o444)
    public.chmod(0o444)
    directory.chmod(0o700)
env = root / ".env"
if not env.exists():
    env.write_text(
        "COMPOSE_PROJECT_NAME=trustpass\nTRUSTPASS_PORT=18120\nAPP_IMAGE=trustpass-platform:local\nGATEWAY_IMAGE=trustpass-gateway:local\n",
        encoding="utf-8",
    )
print("Configuration ready. Keys and tokens are kept in .secrets/ and excluded from Git.")
