"""Exercise the running stack without writing credentials to verification evidence."""

import json
import os
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import httpx

root = Path(__file__).resolve().parents[1]
base = os.getenv("TRUSTPASS_URL", "http://127.0.0.1:18120")
headers = {"Authorization": f"Bearer {(root / '.secrets/api-token').read_text().strip()}"}
checks = []


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)
    print(f"PASS {name}")


def compose(*args):
    subprocess.run(["docker", "compose", *args], cwd=root, check=True, capture_output=True)


def await_events(client, credential_ids, count):
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        response = client.get("/api/v1/events", headers=headers)
        if response.status_code == 200:
            events = [
                event for event in response.json() if event["credential_id"] in credential_ids
            ]
            if len(events) == count:
                return events
        time.sleep(1)
    raise AssertionError("Audit delivery did not converge")


try:
    with httpx.Client(base_url=base, timeout=10) as client:
        check("gateway and dashboard reachable", client.get("/").status_code == 200)
        check(
            "CSP blocks inline scripts",
            "script-src 'self'" in client.get("/").headers["content-security-policy"],
        )
        check(
            "internal endpoints not exposed",
            client.get("/internal/outbox", headers=headers).status_code == 404,
        )
        check("authentication enforced", client.get("/api/v1/credentials").status_code == 401)
        check(
            "contracts exposed",
            all(
                client.get(f"/contracts/{role}.json").json()["openapi"].startswith("3.")
                for role in ("issuer", "verifier", "audit")
            ),
        )
        jwks = client.get("/.well-known/jwks.json").json()
        check("JWKS exposes public key only", "d" not in jwks["keys"][0])
        payload = {
            "subject": f"e2e-{uuid4().hex[:12]}",
            "category": "facility-access",
            "valid_for_seconds": 3600,
        }
        request_headers = {**headers, "Idempotency-Key": str(uuid4()), "X-Request-ID": str(uuid4())}
        issued = client.post("/api/v1/credentials", headers=request_headers, json=payload)
        check(
            "credential issued with correlation",
            issued.status_code == 201
            and issued.headers["X-Request-ID"] == request_headers["X-Request-ID"],
        )
        credential = issued.json()
        replay = client.post("/api/v1/credentials", headers=request_headers, json=payload)
        check(
            "idempotent replay",
            replay.json() == credential and replay.headers.get("Idempotency-Replayed") == "true",
        )
        conflict = client.post(
            "/api/v1/credentials",
            headers=request_headers,
            json={**payload, "valid_for_seconds": 7200},
        )
        check("conflicting reuse rejected", conflict.status_code == 409)
        check(
            "credential verifies",
            client.post(
                "/api/v1/verifications", headers=headers, json={"token": credential["token"]}
            ).json()["valid"],
        )
        parts = credential["token"].split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        check(
            "tampered signature denied",
            client.post(
                "/api/v1/verifications", headers=headers, json={"token": ".".join(parts)}
            ).json()["reason"]
            == "invalid_signature",
        )
        await_events(client, {credential["id"]}, 1)
        compose("stop", "issuer")
        try:
            denied = client.post(
                "/api/v1/verifications", headers=headers, json={"token": credential["token"]}
            )
            check("issuer outage denies verification", denied.status_code == 503)
        finally:
            compose("start", "--wait", "issuer")
        check(
            "idempotency survives container restart",
            client.post("/api/v1/credentials", headers=request_headers, json=payload).json()
            == credential,
        )
        compose("stop", "audit")
        try:
            check(
                "revocation accepted during audit outage",
                client.post(
                    f"/api/v1/credentials/{credential['id']}/revoke", headers=headers
                ).status_code
                == 200,
            )
            second = client.post(
                "/api/v1/credentials",
                headers={**headers, "Idempotency-Key": str(uuid4())},
                json={**payload, "subject": f"e2e-{uuid4().hex[:12]}"},
            ).json()
            check("issuance accepted during audit outage", "token" in second)
            check(
                "revocation effective immediately",
                client.post(
                    "/api/v1/verifications", headers=headers, json={"token": credential["token"]}
                ).json()["reason"]
                == "revoked",
            )
            time.sleep(3)
        finally:
            compose("start", "--wait", "audit")
        events = await_events(client, {credential["id"], second["id"]}, 3)
        check(
            "outbox recovers all events without duplicates",
            len({event["id"] for event in events}) == 3,
        )
        check(
            "audit excludes credential tokens",
            all("token" not in event and "subject" not in event for event in events),
        )
        for service in ("issuer", "verifier", "audit", "gateway"):
            result = subprocess.run(
                ["docker", "compose", "exec", "-T", service, "id", "-u"],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            )
            check(f"{service} runs without root", result.stdout.strip() != "0")
        check(
            "private key absent from verifier",
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "verifier",
                    "test",
                    "!",
                    "-f",
                    "/run/secrets/signing_key",
                ],
                cwd=root,
                capture_output=True,
            ).returncode
            == 0,
        )
        output = root / "artifacts"
        output.mkdir(exist_ok=True)
        (output / "e2e.json").write_text(
            json.dumps({"status": "passed", "checks": checks}, indent=2) + "\n", encoding="utf-8"
        )
finally:
    # Recover deliberately stopped dependencies if any assertion interrupts the scenario.
    compose("start", "issuer", "audit")
print(f"Verified {len(checks)} end-to-end checks.")
