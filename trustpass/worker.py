import asyncio
import json
import logging

import httpx

logger = logging.getLogger("trustpass")


async def deliver_once(store, settings):
    with store.connect() as db:
        rows = db.execute("SELECT id,payload FROM outbox WHERE delivered=0 LIMIT 50").fetchall()
    async with httpx.AsyncClient(timeout=3) as client:
        for row in rows:
            try:
                response = await client.post(
                    f"{settings.audit_url}/internal/events",
                    json=json.loads(row["payload"]),
                    headers={"Authorization": f"Bearer {settings.internal_token}"},
                )
                response.raise_for_status()
            except httpx.HTTPError:
                logger.warning(json.dumps({"event": "outbox_delivery_failed", "id": row["id"]}))
                delivered = 0
            else:
                delivered = 1
            with store.connect() as db:
                db.execute(
                    "UPDATE outbox SET delivered=?, attempts=attempts+1 WHERE id=?",
                    (delivered, row["id"]),
                )


async def run_worker(store, settings):
    while True:
        try:
            await deliver_once(store, settings)
        except Exception:
            logger.exception("Outbox dispatch interrupted; retrying")
        await asyncio.sleep(2)
