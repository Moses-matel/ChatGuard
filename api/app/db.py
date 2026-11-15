import os
from typing import AsyncGenerator
import aiosqlite
import app.config as config_module

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS malicious_hashes (
    sha256 TEXT PRIMARY KEY,
    threat_category TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS malicious_domains (
    domain TEXT PRIMARY KEY COLLATE NOCASE,
    threat_category TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS official_certs (
    cert_sha256 TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    app_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verdict_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    file_type TEXT NOT NULL,
    package_name TEXT,
    cert_sha256 TEXT,
    shown_verdict TEXT NOT NULL,
    user_note TEXT,
    created_at TEXT NOT NULL
);
"""


async def init_db(db_path: str) -> None:
    dirname = os.path.dirname(os.path.abspath(db_path))
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    async with aiosqlite.connect(db_path) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA synchronous=NORMAL;")
        await db.executescript(CREATE_TABLES_SQL)
        await db.commit()


async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    current_settings = getattr(config_module, "settings", None)
    db_path = current_settings.db_path if current_settings else "chatguard.db"
    async with aiosqlite.connect(db_path) as db:
        db.row_factory = aiosqlite.Row
        yield db
