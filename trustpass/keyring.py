"""Locally trusted RSA keys, published as JWKS without accepting token-supplied URLs."""

import json
import re
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def trusted_keys(settings):
    keys = {settings.key_id: Path(settings.public_key).read_bytes()}
    if settings.trusted_keys_dir:
        directory = Path(settings.trusted_keys_dir)
        for path in sorted(directory.glob("*.pem")):
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", path.stem):
                raise ValueError("Invalid trusted key identifier")
            keys[path.stem] = path.read_bytes()
    for value in keys.values():
        key = serialization.load_pem_public_key(value)
        if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
            raise ValueError("Trusted signing keys must be RSA with at least 2048 bits")
    return keys


def jwks(settings):
    return {
        "keys": [
            {
                **json.loads(
                    jwt.algorithms.RSAAlgorithm.to_jwk(serialization.load_pem_public_key(key))
                ),
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
            }
            for kid, key in trusted_keys(settings).items()
        ]
    }
