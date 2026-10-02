"""Prepare RSA rotation. Recreate issuer/verifier together; retain old public keys until expiry."""

import argparse
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def rotate(root, key_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", key_id):
        raise ValueError("Invalid key identifier")
    directory = root / ".secrets"
    ring = directory / "keyring"
    ring.mkdir(exist_ok=True)
    configuration = (root / ".env").read_text(encoding="utf-8")
    old = re.search(r"^SIGNING_KEY_ID=(.+)$", configuration, re.MULTILINE)
    previous_id = old[1] if old else "trustpass-2026-01"
    if previous_id == key_id or (ring / f"{key_id}.pem").exists():
        raise ValueError("Use a fresh key identifier")
    (ring / f"{previous_id}.pem").write_bytes((directory / "verification.pem").read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    (ring / f"{key_id}.pem").write_bytes(public)
    for name, value in (("signing.pem", private), ("verification.pem", public)):
        temporary = directory / (name + ".next")
        temporary.write_bytes(value)
        if os.name != "nt":
            temporary.chmod(0o444)
        temporary.replace(directory / name)
    lines = [line for line in configuration.splitlines() if not line.startswith("SIGNING_KEY_ID=")]
    lines.append(f"SIGNING_KEY_ID={key_id}")
    (root / ".env").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("key_id")
    rotate(Path(__file__).resolve().parents[1], parser.parse_args().key_id)
    print(
        "Rotation prepared. Recreate issuer/verifier together. Keep old public keys until expiry."
    )
