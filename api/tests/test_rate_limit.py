import pytest
from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI
import aiosqlite
import time


@pytest.mark.asyncio
async def test_health_ok():
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_rate_limiter_returns_429_when_exceeded():
    from app.rate_limit import RateLimiterMiddleware

    app = FastAPI()
    app.add_middleware(RateLimiterMiddleware, requests_limit=3, window_seconds=10)

    @app.get("/test")
    async def endpoint():
        return {"ok": True}

    transport = ASGITransport(app=app, client=("192.168.1.100", 50000))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First 3 requests succeed
        for _ in range(3):
            res = await client.get("/test")
            assert res.status_code == 200

        # 4th request within window must be rate limited
        res = await client.get("/test")
        assert res.status_code == 429
        data = res.json()
        assert "detail" in data or "error" in data


@pytest.mark.asyncio
async def test_rate_limiter_per_ip_isolation():
    from app.rate_limit import RateLimiterMiddleware

    app = FastAPI()
    app.add_middleware(RateLimiterMiddleware, requests_limit=2, window_seconds=10)

    @app.get("/test")
    async def endpoint():
        return {"ok": True}

    ip1_transport = ASGITransport(app=app, client=("10.0.0.1", 50000))
    ip2_transport = ASGITransport(app=app, client=("10.0.0.2", 50000))

    async with AsyncClient(transport=ip1_transport, base_url="http://test") as client1:
        res1 = await client1.get("/test")
        assert res1.status_code == 200
        res2 = await client1.get("/test")
        assert res2.status_code == 200
        res3 = await client1.get("/test")
        assert res3.status_code == 429

    # ip2 should not be affected by ip1
    async with AsyncClient(transport=ip2_transport, base_url="http://test") as client2:
        res_ip2 = await client2.get("/test")
        assert res_ip2.status_code == 200


@pytest.mark.asyncio
async def test_init_db_creates_tables(temp_db_path):
    from app.db import init_db

    await init_db(temp_db_path)

    async with aiosqlite.connect(temp_db_path) as db:
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        tables = [row[0] for row in await cursor.fetchall()]

        assert "malicious_hashes" in tables
        assert "malicious_domains" in tables
        assert "official_certs" in tables
        assert "verdict_reports" in tables

        # Verify malicious_hashes schema
        cursor = await db.execute("PRAGMA table_info(malicious_hashes);")
        cols = {row[1]: row[2] for row in await cursor.fetchall()}
        assert "sha256" in cols
        assert "threat_category" in cols

        # Verify malicious_domains schema
        cursor = await db.execute("PRAGMA table_info(malicious_domains);")
        cols = {row[1]: row[2] for row in await cursor.fetchall()}
        assert "domain" in cols
        assert "threat_category" in cols

        # Verify official_certs schema
        cursor = await db.execute("PRAGMA table_info(official_certs);")
        cols = {row[1]: row[2] for row in await cursor.fetchall()}
        assert "cert_sha256" in cols
        assert "package_name" in cols
        assert "app_name" in cols

        # Verify verdict_reports schema
        cursor = await db.execute("PRAGMA table_info(verdict_reports);")
        cols = {row[1]: row[2] for row in await cursor.fetchall()}
        assert "id" in cols
        assert "sha256" in cols
        assert "file_type" in cols
        assert "package_name" in cols
        assert "cert_sha256" in cols
        assert "shown_verdict" in cols
        assert "user_note" in cols
        assert "created_at" in cols


@pytest.mark.asyncio
async def test_get_db(temp_db_path, monkeypatch):
    from app.db import init_db, get_db
    from app.config import Settings
    import app.config as config_mod

    await init_db(temp_db_path)

    test_settings = Settings(db_path=temp_db_path)
    monkeypatch.setattr(config_mod, "settings", test_settings)

    # get_db is an async generator
    async for db in get_db():
        cursor = await db.execute("SELECT 1;")
        row = await cursor.fetchone()
        assert row[0] == 1
        break
