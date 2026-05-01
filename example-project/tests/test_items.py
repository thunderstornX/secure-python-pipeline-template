from fastapi.testclient import TestClient


_USER = {"username": "bob", "email": "bob@example.com", "password": "Str0ngPass99!"}
_ITEM = {"name": "Gadget", "description": "A test gadget", "price": 9.99}


def _create_user(client: TestClient) -> int:
    return client.post("/users/", json=_USER).json()["id"]


def test_create_item_returns_201(client: TestClient) -> None:
    owner_id = _create_user(client)
    r = client.post("/items/", json=_ITEM, params={"owner_id": owner_id})
    assert r.status_code == 201
    body = r.json()
    assert body["name"] == "Gadget"
    assert body["owner_id"] == owner_id


def test_create_item_unknown_owner_returns_404(client: TestClient) -> None:
    r = client.post("/items/", json=_ITEM, params={"owner_id": 9999})
    assert r.status_code == 404


def test_get_item(client: TestClient) -> None:
    owner_id = _create_user(client)
    item_id = client.post("/items/", json=_ITEM, params={"owner_id": owner_id}).json()["id"]
    r = client.get(f"/items/{item_id}")
    assert r.status_code == 200
    assert r.json()["price"] == 9.99


def test_delete_item(client: TestClient) -> None:
    owner_id = _create_user(client)
    item_id = client.post("/items/", json=_ITEM, params={"owner_id": owner_id}).json()["id"]
    r = client.delete(f"/items/{item_id}")
    assert r.status_code == 204
    assert client.get(f"/items/{item_id}").status_code == 404


def test_item_price_validation(client: TestClient) -> None:
    owner_id = _create_user(client)
    bad = {**_ITEM, "price": -1.0}
    r = client.post("/items/", json=bad, params={"owner_id": owner_id})
    assert r.status_code == 422


def test_list_items(client: TestClient) -> None:
    owner_id = _create_user(client)
    client.post("/items/", json=_ITEM, params={"owner_id": owner_id})
    r = client.get("/items/")
    assert r.status_code == 200
    assert len(r.json()) >= 1
