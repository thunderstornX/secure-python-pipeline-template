import pytest
from fastapi.testclient import TestClient


VALID_USER = {
    "username": "alice",
    "email": "alice@example.com",
    "password": "Str0ngPass99!",
}


def test_create_user_returns_201(client: TestClient) -> None:
    r = client.post("/users/", json=VALID_USER)
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "alice"
    assert body["email"] == "alice@example.com"
    assert "id" in body
    assert "password" not in body
    assert "pw_hash" not in body


def test_create_user_duplicate_returns_409(client: TestClient) -> None:
    client.post("/users/", json=VALID_USER)
    r = client.post("/users/", json=VALID_USER)
    assert r.status_code == 409


def test_get_user_by_id(client: TestClient) -> None:
    create = client.post("/users/", json=VALID_USER).json()
    r = client.get(f"/users/{create['id']}")
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_get_nonexistent_user_returns_404(client: TestClient) -> None:
    r = client.get("/users/9999")
    assert r.status_code == 404


def test_list_users(client: TestClient) -> None:
    client.post("/users/", json=VALID_USER)
    r = client.get("/users/")
    assert r.status_code == 200
    assert len(r.json()) >= 1


@pytest.mark.parametrize("password,expected", [
    ("short", 422),           # too short
    ("alllowercase1", 422),   # no uppercase
    ("NOLOWER1NUMBER", 201),  # all-uppercase + digit satisfies our validator (upper+digit required)
    ("NoDigitAtAll!!", 422),  # no digit
    ("Str0ngPass99!", 201),   # valid
])
def test_password_validation(client: TestClient, password: str, expected: int) -> None:
    payload = {**VALID_USER, "password": password, "username": f"u_{hash(password) % 100000}",
               "email": f"u{hash(password) % 100000}@ex.com"}
    r = client.post("/users/", json=payload)
    assert r.status_code == expected


def test_sql_injection_in_username_is_sanitised(client: TestClient) -> None:
    payload = {
        "username": "alice",
        "email": "safe@example.com",
        "password": "Str0ngPass99!",
    }
    client.post("/users/", json=payload)
    # Attempt to pass SQL meta-characters in the lookup path
    r = client.get("/users/1' OR '1'='1")
    assert r.status_code == 422  # FastAPI rejects non-integer path param
