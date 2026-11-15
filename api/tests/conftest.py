import os
import tempfile
import pytest
from httpx import AsyncClient, ASGITransport

@pytest.fixture
def temp_db_path(tmp_path):
    db_file = tmp_path / "test_chatguard.db"
    return str(db_file)

@pytest.fixture
async def test_client():
    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
