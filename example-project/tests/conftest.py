import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import database
from pathlib import Path


@pytest.fixture(autouse=True)
def clean_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "_DB_PATH", db_path)
    database.init_db()
    yield
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
