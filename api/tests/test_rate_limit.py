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
async def test_rate_limiter_exempts_health_while_limiting_v1_routes():
    from app.rate_limit import RateLimiterMiddleware

    app = FastAPI()
    app.add_middleware(RateLimiterMiddleware, requests_limit=2, window_seconds=10)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/v1/check")
    async def check():
        return {"verdict": "unknown"}

    transport = ASGITransport(app=app, client=("192.168.1.101", 50000))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Exhaust /v1/check limit
        for _ in range(2):
            res = await client.post("/v1/check")
            assert res.status_code == 200

        blocked = await client.post("/v1/check")
        assert blocked.status_code == 429

        # /health must remain exempt even when IP is rate-limited
        for _ in range(5):
            health_res = await client.get("/health")
            assert health_res.status_code == 200
            assert health_res.json() == {"status": "ok"}

        # /v1/check is still rate-limited
        still_blocked = await client.post("/v1/check")
        assert still_blocked.status_code == 429


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
        assert "retry-after" in res.headers
        retry_after = int(res.headers["retry-after"])
        assert 1 <= retry_after <= 10


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
async def test_rate_limiter_ignores_x_forwarded_for_when_untrusted():
    from app.rate_limit import RateLimiterMiddleware

    app = FastAPI()
    # Default trust_proxy_headers=False
    app.add_middleware(
        RateLimiterMiddleware, requests_limit=2, window_seconds=10, trust_proxy_headers=False
    )

    @app.get("/test")
    async def endpoint():
        return {"ok": True}

    transport = ASGITransport(app=app, client=("192.168.1.50", 50000))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Spoofing X-Forwarded-For should NOT bypass the limit
        res1 = await client.get("/test", headers={"x-forwarded-for": "1.1.1.1"})
        assert res1.status_code == 200
        res2 = await client.get("/test", headers={"x-forwarded-for": "2.2.2.2"})
        assert res2.status_code == 200
        res3 = await client.get("/test", headers={"x-forwarded-for": "3.3.3.3"})
        # Must be 429 because physical IP 192.168.1.50 exceeded limit
        assert res3.status_code == 429


@pytest.mark.asyncio
async def test_rate_limiter_honors_x_forwarded_for_when_trusted():
    from app.rate_limit import RateLimiterMiddleware

    app = FastAPI()
    app.add_middleware(
        RateLimiterMiddleware, requests_limit=2, window_seconds=10, trust_proxy_headers=True
    )

    @app.get("/test")
    async def endpoint():
        return {"ok": True}

    # Same physical proxy client
    transport = ASGITransport(app=app, client=("10.0.0.1", 50000))
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Client 1.1.1.1 uses 2 requests
        await client.get("/test", headers={"x-forwarded-for": "1.1.1.1"})
        await client.get("/test", headers={"x-forwarded-for": "1.1.1.1"})
        blocked = await client.get("/test", headers={"x-forwarded-for": "1.1.1.1"})
        assert blocked.status_code == 429

        # Client 2.2.2.2 is not blocked
        allowed = await client.get("/test", headers={"x-forwarded-for": "2.2.2.2"})
        assert allowed.status_code == 200


@pytest.mark.asyncio
async def test_rate_limiter_evicts_idle_ips_and_caps_entries():
    from app.rate_limit import RateLimiterMiddleware

    middleware = RateLimiterMiddleware(
        FastAPI(), requests_limit=5, window_seconds=0.1, max_tracked_ips=2
    )

    # Directly manipulate history to test pruning and eviction
    now = time.monotonic()
    middleware._history["old_ip"] = [now - 1.0]  # Expired
    middleware._history["ip1"] = [now]
    middleware._history["ip2"] = [now]

    # Prune and bound-check
    middleware._cleanup(now)

    # "old_ip" should have been removed because it was expired
    assert "old_ip" not in middleware._history
    # Total tracked IPs must not exceed max_tracked_ips (2)
    assert len(middleware._history) <= 2


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


@pytest.mark.asyncio
async def test_init_db_enables_wal_and_nocase_domains(temp_db_path):
    from app.db import init_db

    await init_db(temp_db_path)

    async with aiosqlite.connect(temp_db_path) as db:
        cursor = await db.execute("PRAGMA journal_mode;")
        row = await cursor.fetchone()
        assert row[0].lower() == "wal"

        await db.execute(
            "INSERT INTO malicious_domains (domain, threat_category) VALUES (?, ?)",
            ("Phish.Example.COM", "phishing"),
        )
        await db.commit()

        cursor = await db.execute(
            "SELECT threat_category FROM malicious_domains WHERE domain = ?",
            ("phish.example.com",),
        )
        match = await cursor.fetchone()
        assert match is not None
        assert match[0] == "phishing"
