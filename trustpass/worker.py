import asyncio
import json
import logging
import random
import time

import httpx

logger = logging.getLogger("trustpass")


async def deliver_once(store, settings, now=None):
    current = time.time() if now is None else now
    with store.connect() as db:
        rows = db.execute(
            "SELECT id,payload,attempts FROM outbox WHERE delivered=0 AND dead_letter=0 "
            "AND next_attempt_at<=? ORDER BY next_attempt_at,rowid LIMIT 50",
            (current,),
        ).fetchall()
    async with httpx.AsyncClient(timeout=3) as client:
        for row in rows:
            try:
                response = await client.post(
                    f"{settings.audit_url}/internal/events",
                    json=json.loads(row["payload"]),
                    headers={"Authorization": f"Bearer {settings.internal_token}"},
                )
                response.raise_for_status()
            except httpx.HTTPError as error:
                logger.warning(json.dumps({"event": "outbox_delivery_failed", "id": row["id"]}))
                delivered = 0
                last_error = type(error).__name__
            else:
                delivered = 1
                last_error = None
            attempts = row["attempts"] + 1
            dead = int(not delivered and attempts >= settings.max_delivery_attempts)
            next_attempt = current + min(300, 2 ** min(attempts, 8)) + random.uniform(0, 1)
            with store.connect() as db:
                db.execute(
                    "UPDATE outbox SET delivered=?, attempts=?, next_attempt_at=?, "
                    "dead_letter=?,last_error=? WHERE id=?",
                    (delivered, attempts, next_attempt, dead, last_error, row["id"]),
                )


async def run_worker(store, settings):
    while True:
        try:
            await deliver_once(store, settings)
        except Exception:
            logger.exception("Outbox dispatch interrupted; retrying")
        await asyncio.sleep(2)
