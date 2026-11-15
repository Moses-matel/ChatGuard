import pytest
import aiosqlite
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db import init_db
from app.config import Settings
import app.config as config_mod

VALID_HASH = "a" * 64
VALID_CERT = "b" * 64


@pytest.fixture
async def setup_test_db(temp_db_path, monkeypatch):
    """Initializes tables in a temporary database for test isolation."""
    await init_db(temp_db_path)
    test_settings = Settings(db_path=temp_db_path)
    monkeypatch.setattr(config_mod, "settings", test_settings)
    return temp_db_path


@pytest.fixture
async def client(setup_test_db):
    transport = ASGITransport(app=app, client=("192.168.1.60", 46000))
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_report_valid_metadata_recorded_successfully(client, setup_test_db):
    payload = {
        "sha256": VALID_HASH,
        "file_type": "apk",
        "package_name": "com.secure.bank",
        "cert_sha256": VALID_CERT,
        "shown_verdict": "BERBAHAYA",
        "user_note": "Aplikasi perbankan resmi tapi terdeteksi berbahaya",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 201
    assert response.json() == {"status": "recorded"}

    # Verify persistence in SQLite table
    async with aiosqlite.connect(setup_test_db) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM verdict_reports WHERE sha256 = ?", (VALID_HASH,)) as cursor:
            row = await cursor.fetchone()
            assert row is not None
            assert row["sha256"] == VALID_HASH
            assert row["file_type"] == "apk"
            assert row["package_name"] == "com.secure.bank"
            assert row["cert_sha256"] == VALID_CERT
            assert row["shown_verdict"] == "BERBAHAYA"
            assert row["user_note"] == "Aplikasi perbankan resmi tapi terdeteksi berbahaya"
            assert row["created_at"] is not None


@pytest.mark.asyncio
async def test_report_minimal_valid_metadata_succeeds(client, setup_test_db):
    payload = {
        "sha256": "c" * 64,
        "file_type": "pdf",
        "shown_verdict": "AMAN",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 201
    assert response.json() == {"status": "recorded"}

    async with aiosqlite.connect(setup_test_db) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM verdict_reports WHERE sha256 = ?", ("c" * 64,)) as cursor:
            row = await cursor.fetchone()
            assert row is not None
            assert row["file_type"] == "pdf"
            assert row["package_name"] is None
            assert row["cert_sha256"] is None
            assert row["user_note"] is None
            assert row["shown_verdict"] == "AMAN"


@pytest.mark.asyncio
@pytest.mark.parametrize("file_type", ["apk", "pdf", "office", "archive", "unknown"])
async def test_report_all_allowed_file_types(client, file_type):
    payload = {
        "sha256": "d" * 64,
        "file_type": file_type,
        "shown_verdict": "MENCURIGAKAN",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 201
    assert response.json() == {"status": "recorded"}


@pytest.mark.asyncio
@pytest.mark.parametrize("shown_verdict", ["AMAN", "MENCURIGAKAN", "BERBAHAYA"])
async def test_report_all_allowed_shown_verdicts(client, shown_verdict):
    payload = {
        "sha256": "e" * 64,
        "file_type": "apk",
        "shown_verdict": shown_verdict,
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 201
    assert response.json() == {"status": "recorded"}


@pytest.mark.asyncio
async def test_report_invalid_file_type_returns_422(client):
    payload = {
        "sha256": VALID_HASH,
        "file_type": "executable",
        "shown_verdict": "BERBAHAYA",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_invalid_shown_verdict_returns_422(client):
    payload = {
        "sha256": VALID_HASH,
        "file_type": "apk",
        "shown_verdict": "CLEAN",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_user_note_at_500_char_boundary_succeeds(client):
    payload = {
        "sha256": "f" * 64,
        "file_type": "pdf",
        "shown_verdict": "AMAN",
        "user_note": "n" * 500,
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_report_user_note_exceeding_500_chars_returns_422(client):
    payload = {
        "sha256": VALID_HASH,
        "file_type": "apk",
        "shown_verdict": "BERBAHAYA",
        "user_note": "x" * 501,
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_malformed_sha256_returns_422(client):
    # Too short
    res1 = await client.post("/v1/report", json={"sha256": "abc123", "file_type": "apk", "shown_verdict": "AMAN"})
    assert res1.status_code == 422

    # Non-hex characters
    res2 = await client.post("/v1/report", json={"sha256": "g" * 64, "file_type": "apk", "shown_verdict": "AMAN"})
    assert res2.status_code == 422

    # Missing required sha256
    res3 = await client.post("/v1/report", json={"file_type": "apk", "shown_verdict": "AMAN"})
    assert res3.status_code == 422


@pytest.mark.asyncio
async def test_report_malformed_cert_sha256_returns_422(client):
    payload = {
        "sha256": VALID_HASH,
        "file_type": "apk",
        "cert_sha256": "not-a-valid-cert-hash",
        "shown_verdict": "BERBAHAYA",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_extra_fields_rejected_with_422(client):
    payload = {
        "sha256": VALID_HASH,
        "file_type": "apk",
        "shown_verdict": "BERBAHAYA",
        "unexpected_field": "malicious_injection",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_hex_normalized_to_lowercase(client, setup_test_db):
    upper_hash = VALID_HASH.upper()
    upper_cert = VALID_CERT.upper()
    payload = {
        "sha256": upper_hash,
        "file_type": "apk",
        "cert_sha256": upper_cert,
        "shown_verdict": "BERBAHAYA",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 201

    async with aiosqlite.connect(setup_test_db) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT sha256, cert_sha256 FROM verdict_reports WHERE sha256 = ?", (VALID_HASH.lower(),)) as cursor:
            row = await cursor.fetchone()
            assert row is not None
            assert row["sha256"] == VALID_HASH.lower()
            assert row["cert_sha256"] == VALID_CERT.lower()


@pytest.mark.asyncio
async def test_report_rejects_multipart_body(client):
    response = await client.post(
        "/v1/report",
        files={"file": ("report_sample.apk", b"PK\x03\x04fakebinarycontent")},
    )
    assert response.status_code in (415, 422)


@pytest.mark.asyncio
async def test_report_rejects_raw_binary_body(client):
    response = await client.post(
        "/v1/report",
        content=b"\x7fELFfakebinary",
        headers={"content-type": "application/octet-stream"},
    )
    assert response.status_code in (415, 422)


@pytest.mark.asyncio
async def test_report_android_camelcase_payload_recorded_successfully(client, setup_test_db):
    payload = {
        "sha256": VALID_HASH,
        "fileType": "APK",
        "packageName": "com.fake.bank",
        "certSha256": VALID_CERT,
        "shownVerdict": "BERBAHAYA",
        "userNote": "Suspicious APK from chat",
    }
    response = await client.post("/v1/report", json=payload)
    assert response.status_code == 201
    assert response.json() == {"status": "recorded"}

    async with aiosqlite.connect(setup_test_db) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM verdict_reports WHERE sha256 = ?", (VALID_HASH,)) as cursor:
            row = await cursor.fetchone()
            assert row is not None
            assert row["file_type"] == "apk"
            assert row["package_name"] == "com.fake.bank"
            assert row["cert_sha256"] == VALID_CERT
            assert row["shown_verdict"] == "BERBAHAYA"
            assert row["user_note"] == "Suspicious APK from chat"
