import pytest
import aiosqlite
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db import init_db
from app.config import Settings
import app.config as config_mod

MALICIOUS_HASH = "a" * 64
MALICIOUS_DOMAIN = "malicious-phish.com"
OFFICIAL_CERT = "b" * 64
CLEAN_HASH = "c" * 64


@pytest.fixture
async def setup_test_db(temp_db_path, monkeypatch):
    """Initializes tables and seeds test fixtures for reputation checks."""
    await init_db(temp_db_path)
    test_settings = Settings(db_path=temp_db_path)
    monkeypatch.setattr(config_mod, "settings", test_settings)

    async with aiosqlite.connect(temp_db_path) as db:
        await db.execute(
            "INSERT INTO malicious_hashes (sha256, threat_category) VALUES (?, ?)",
            (MALICIOUS_HASH, "trojan.banker"),
        )
        await db.execute(
            "INSERT INTO malicious_domains (domain, threat_category) VALUES (?, ?)",
            (MALICIOUS_DOMAIN, "phishing"),
        )
        await db.execute(
            "INSERT INTO official_certs (cert_sha256, package_name, app_name) VALUES (?, ?, ?)",
            (OFFICIAL_CERT, "com.secure.bank", "Secure Bank Official"),
        )
        await db.commit()

    return temp_db_path


@pytest.fixture
async def client(setup_test_db):
    transport = ASGITransport(app=app, client=("192.168.1.50", 45000))
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_check_unknown_hash_clean_url_returns_unknown(client):
    payload = {
        "sha256": CLEAN_HASH,
        "urls": ["https://safe-domain.org/path/index.html"],
    }
    response = await client.post("/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "unknown"
    assert data["threat_category"] is None
    assert data["official_cert_match"] is None
    assert data["flagged_urls"] == []


@pytest.mark.asyncio
async def test_check_malicious_hash_returns_malicious(client):
    payload = {"sha256": MALICIOUS_HASH}
    response = await client.post("/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "malicious"
    assert data["threat_category"] == "trojan.banker"
    assert data["official_cert_match"] is None
    assert data["flagged_urls"] == []


@pytest.mark.asyncio
async def test_check_malicious_url_exact_domain_returns_malicious(client):
    payload = {
        "urls": [
            f"https://{MALICIOUS_DOMAIN}/login",
            "https://legit-example.com/welcome",
        ]
    }
    response = await client.post("/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "malicious"
    assert data["threat_category"] == "phishing"
    assert data["flagged_urls"] == [f"https://{MALICIOUS_DOMAIN}/login"]


@pytest.mark.asyncio
async def test_check_malicious_url_subdomain_returns_malicious(client):
    subdomain_url = f"https://sub.portal.{MALICIOUS_DOMAIN}/verify"
    payload = {"urls": [subdomain_url]}
    response = await client.post("/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "malicious"
    assert data["threat_category"] == "phishing"
    assert data["flagged_urls"] == [subdomain_url]


@pytest.mark.asyncio
async def test_check_official_cert_match_returns_clean(client):
    payload = {"cert_sha256": OFFICIAL_CERT}
    response = await client.post("/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "clean"
    assert data["official_cert_match"] is True
    assert data["threat_category"] is None
    assert data["flagged_urls"] == []


@pytest.mark.asyncio
async def test_check_official_cert_not_found_returns_unknown(client):
    payload = {"cert_sha256": "f" * 64}
    response = await client.post("/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "unknown"
    assert data["official_cert_match"] is False
    assert data["threat_category"] is None
    assert data["flagged_urls"] == []


@pytest.mark.asyncio
async def test_check_official_cert_with_malicious_hash_returns_malicious(client):
    payload = {
        "sha256": MALICIOUS_HASH,
        "cert_sha256": OFFICIAL_CERT,
    }
    response = await client.post("/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "malicious"
    assert data["threat_category"] == "trojan.banker"
    assert data["official_cert_match"] is True


@pytest.mark.asyncio
async def test_check_official_cert_with_malicious_url_returns_malicious(client):
    payload = {
        "cert_sha256": OFFICIAL_CERT,
        "urls": [f"http://{MALICIOUS_DOMAIN}/update.apk"],
    }
    response = await client.post("/v1/check", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "malicious"
    assert data["official_cert_match"] is True
    assert data["flagged_urls"] == [f"http://{MALICIOUS_DOMAIN}/update.apk"]


@pytest.mark.asyncio
async def test_check_malformed_sha256_returns_422(client):
    # Too short
    res1 = await client.post("/v1/check", json={"sha256": "abc123"})
    assert res1.status_code == 422

    # Non-hex characters
    res2 = await client.post("/v1/check", json={"sha256": "g" * 64})
    assert res2.status_code == 422


@pytest.mark.asyncio
async def test_check_malformed_cert_sha256_returns_422(client):
    # 65 chars
    res = await client.post("/v1/check", json={"cert_sha256": "a" * 65})
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_check_more_than_50_urls_returns_422(client):
    payload = {"urls": [f"https://site{i}.org" for i in range(51)]}
    res = await client.post("/v1/check", json=payload)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_check_unexpected_fields_returns_422(client):
    payload = {"sha256": CLEAN_HASH, "unknown_field": "rejected"}
    res = await client.post("/v1/check", json=payload)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_check_rejects_multipart_body(client):
    res = await client.post(
        "/v1/check",
        files={"file": ("malware.apk", b"PK\x03\x04fakebinary")},
    )
    assert res.status_code in (415, 422)


@pytest.mark.asyncio
async def test_check_rejects_raw_binary_body(client):
    res = await client.post(
        "/v1/check",
        content=b"\x00\x01\x02\x03",
        headers={"content-type": "application/octet-stream"},
    )
    assert res.status_code in (415, 422)


@pytest.mark.asyncio
async def test_check_empty_request_body_returns_unknown(client):
    res = await client.post("/v1/check", json={})
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "unknown"
    assert data["official_cert_match"] is None
    assert data["threat_category"] is None
    assert data["flagged_urls"] == []


@pytest.mark.asyncio
async def test_check_case_insensitive_hex_matching(client):
    payload = {
        "sha256": MALICIOUS_HASH.upper(),
        "cert_sha256": OFFICIAL_CERT.upper(),
    }
    res = await client.post("/v1/check", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "malicious"
    assert data["official_cert_match"] is True
