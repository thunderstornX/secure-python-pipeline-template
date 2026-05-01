import sqlite3
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

_DB_PATH = Path(__file__).parent.parent / "example.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH))
    # WAL mode: better concurrency, crash-safe
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                email    TEXT    NOT NULL UNIQUE,
                pw_hash  TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS items (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                description TEXT    NOT NULL DEFAULT '',
                price       REAL    NOT NULL,
                owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
            );
        """)


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
