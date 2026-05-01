from fastapi import APIRouter, HTTPException, status
from app.models import ItemCreate, ItemResponse
from app.database import get_db

router = APIRouter(prefix="/items", tags=["items"])


@router.post("/", response_model=ItemResponse, status_code=status.HTTP_201_CREATED)
def create_item(payload: ItemCreate, owner_id: int) -> ItemResponse:
    with get_db() as conn:
        row = conn.execute("SELECT id FROM users WHERE id = ?", (owner_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Owner not found.")
        cursor = conn.execute(
            "INSERT INTO items (name, description, price, owner_id) VALUES (?, ?, ?, ?)",
            (payload.name, payload.description, payload.price, owner_id),
        )
        item_id = cursor.lastrowid
    return ItemResponse(
        id=item_id,
        name=payload.name,
        description=payload.description,
        price=payload.price,
        owner_id=owner_id,
    )


@router.get("/{item_id}", response_model=ItemResponse)
def get_item(item_id: int) -> ItemResponse:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, name, description, price, owner_id FROM items WHERE id = ?",
            (item_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found.")
    return ItemResponse(**dict(row))


@router.get("/", response_model=list[ItemResponse])
def list_items(limit: int = 20, offset: int = 0) -> list[ItemResponse]:
    limit = min(max(limit, 1), 100)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, description, price, owner_id FROM items LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [ItemResponse(**dict(r)) for r in rows]


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(item_id: int) -> None:
    with get_db() as conn:
        result = conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found.")
