import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self, role: str):
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            if role == "issuer":
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS credentials (
                        id TEXT PRIMARY KEY, subject TEXT NOT NULL, category TEXT NOT NULL,
                        expires_at INTEGER NOT NULL, status TEXT NOT NULL, token TEXT NOT NULL,
                        created_at INTEGER NOT NULL, revoked_at INTEGER
                    );
                    CREATE TABLE IF NOT EXISTS requests (
                        key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, response TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS outbox (
                        id TEXT PRIMARY KEY, payload TEXT NOT NULL, delivered INTEGER DEFAULT 0,
                        attempts INTEGER DEFAULT 0
                    );
                """)
            if role == "audit":
                db.execute("""CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, credential_id TEXT NOT NULL,
                    event_type TEXT NOT NULL, occurred_at INTEGER NOT NULL,
                    request_id TEXT NOT NULL
                )""")

    @staticmethod
    def enqueue(db, event):
        db.execute("INSERT INTO outbox(id,payload) VALUES (?,?)", (event["id"], json.dumps(event)))
