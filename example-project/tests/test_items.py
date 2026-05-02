from fastapi.testclient import TestClient


_USER = {"username": "bob", "email": "bob@example.com", "password": "Str0ngPass99!"}
_OTHER_USER = {"username": "eve", "email": "eve@example.com", "password": "Str0ngPass99!"}
_ITEM = {"name": "Gadget", "description": "A test gadget", "price": 9.99}


def _login(client: TestClient, user: dict) -> str:
    client.post("/users/", json=user)
    r = client.post("/users/login", json={
        "username": user["username"],
        "password": user["password"],
    })
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_create_item_requires_auth(client: TestClient) -> None:
    """No Authorization header at all: HTTPBearer rejects with 401/403
    depending on Starlette version. Either is correct (caller is
    not authenticated)."""
    r = client.post("/items/", json=_ITEM)
    assert r.status_code in (401, 403)


def test_create_item_with_valid_token_returns_201(client: TestClient) -> None:
    token = _login(client, _USER)
    r = client.post("/items/", json=_ITEM, headers=_auth(token))
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == "Gadget"
    # owner_id is derived from the token, NOT from the request -- IDOR-safe
    assert isinstance(body["owner_id"], int)


def test_create_item_with_bad_token_returns_401(client: TestClient) -> None:
    r = client.post("/items/", json=_ITEM, headers=_auth("not.a.real.token"))
    assert r.status_code == 401


def test_create_item_with_tampered_token_returns_401(client: TestClient) -> None:
    token = _login(client, _USER)
    # Flip a byte in the signature; HMAC verify must reject.
    body, sig = token.rsplit(".", 1)
    tampered = f"{body}.{sig[:-1]}{'a' if sig[-1] != 'a' else 'b'}"
    r = client.post("/items/", json=_ITEM, headers=_auth(tampered))
    assert r.status_code == 401


def test_get_item(client: TestClient) -> None:
    token = _login(client, _USER)
    item_id = client.post("/items/", json=_ITEM, headers=_auth(token)).json()["id"]
    r = client.get(f"/items/{item_id}")
    assert r.status_code == 200
    assert r.json()["price"] == 9.99


def test_delete_item_owner_succeeds(client: TestClient) -> None:
    token = _login(client, _USER)
    item_id = client.post("/items/", json=_ITEM, headers=_auth(token)).json()["id"]
    r = client.delete(f"/items/{item_id}", headers=_auth(token))
    assert r.status_code == 204
    assert client.get(f"/items/{item_id}").status_code == 404


def test_delete_item_other_user_returns_404(client: TestClient) -> None:
    """Authorisation: a different authenticated user cannot delete bob's item."""
    bob_token = _login(client, _USER)
    eve_token = _login(client, _OTHER_USER)
    item_id = client.post("/items/", json=_ITEM, headers=_auth(bob_token)).json()["id"]

    r = client.delete(f"/items/{item_id}", headers=_auth(eve_token))
    assert r.status_code == 404
    # Item still exists for the real owner
    assert client.get(f"/items/{item_id}").status_code == 200


def test_item_price_validation(client: TestClient) -> None:
    token = _login(client, _USER)
    bad = {**_ITEM, "price": -1.0}
    r = client.post("/items/", json=bad, headers=_auth(token))
    assert r.status_code == 422


def test_list_items(client: TestClient) -> None:
    token = _login(client, _USER)
    client.post("/items/", json=_ITEM, headers=_auth(token))
    r = client.get("/items/")
    assert r.status_code == 200
    assert len(r.json()) >= 1
