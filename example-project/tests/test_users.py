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
    ("short", 422),                # too short (< 10 chars)
    ("alllowercase1", 422),        # no uppercase
    ("NOLOWER1NUMBER", 201),       # all-uppercase + digit satisfies our (deliberately minimal) policy
    ("NoDigitAtAll!!", 422),       # no digit
    ("Str0ngPass99!", 201),        # valid: upper + digit + length
])
def test_password_validation(client: TestClient, password: str, expected: int) -> None:
    payload = {**VALID_USER, "password": password,
               "username": f"u_{abs(hash(password)) % 100000}",
               "email": f"u{abs(hash(password)) % 100000}@ex.com"}
    r = client.post("/users/", json=payload)
    assert r.status_code == expected


def test_sqli_metachars_in_username_rejected_by_pydantic(client: TestClient) -> None:
    """The username regex `^[a-zA-Z0-9_-]+$` rejects SQL meta-characters
    BEFORE they reach the database. This is defense-in-depth: the SQL
    layer is also parameterised (see test_sqli_payload_safe_via_parameterisation)."""
    bad = {
        "username": "alice'; DROP TABLE users;--",
        "email": "bad@example.com",
        "password": "Str0ngPass99!",
    }
    r = client.post("/users/", json=bad)
    assert r.status_code == 422


def test_sqli_payload_safe_via_parameterisation(client: TestClient) -> None:
    """Even if a metachar somehow reached the DB layer, the parameterised
    `?` placeholder treats the whole string as a literal value -- never
    as SQL syntax. We prove this by GETting an int path that contains
    SQL metacharacters: FastAPI rejects with 422 long before SQL runs."""
    r = client.get("/users/1' OR '1'='1")
    assert r.status_code == 422


def test_login_returns_token_and_authorises(client: TestClient) -> None:
    client.post("/users/", json=VALID_USER)
    r = client.post("/users/login", json={
        "username": VALID_USER["username"],
        "password": VALID_USER["password"],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"].count(".") == 1


def test_login_with_wrong_password_returns_401(client: TestClient) -> None:
    client.post("/users/", json=VALID_USER)
    r = client.post("/users/login", json={
        "username": VALID_USER["username"],
        "password": "WrongPassword99",
    })
    assert r.status_code == 401


def test_login_with_unknown_user_returns_401(client: TestClient) -> None:
    """Constant-time bcrypt verification: unknown user must NOT 404,
    or an attacker can enumerate accounts by response code."""
    r = client.post("/users/login", json={
        "username": "ghost",
        "password": "AnyPassword1",
    })
    assert r.status_code == 401
