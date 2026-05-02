"""
Item CRUD.  Demonstrates:

- All write operations require an authenticated user (no IDOR via query
  param).  ``current_user_id`` is derived from the bearer token issued by
  ``POST /users/login`` and cannot be spoofed by the caller.
- Parameterised SQL throughout.
- Pydantic field constraints reject negative or absurd prices.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import current_user_id
from app.database import get_db
from app.models import ItemCreate, ItemResponse

router = APIRouter(prefix="/items", tags=["items"])


@router.post("/", response_model=ItemResponse, status_code=status.HTTP_201_CREATED)
def create_item(
    payload: ItemCreate,
    user_id: Annotated[int, Depends(current_user_id)],
) -> ItemResponse:
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO items (name, description, price, owner_id) VALUES (?, ?, ?, ?)",
            (payload.name, payload.description, payload.price, user_id),
        )
        item_id = cursor.lastrowid
    return ItemResponse(
        id=item_id,
        name=payload.name,
        description=payload.description,
        price=payload.price,
        owner_id=user_id,
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
    offset = max(offset, 0)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, description, price, owner_id FROM items LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [ItemResponse(**dict(r)) for r in rows]


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(
    item_id: int,
    user_id: Annotated[int, Depends(current_user_id)],
) -> None:
    """Owner-only delete: deleting another user's item returns 404."""
    with get_db() as conn:
        result = conn.execute(
            "DELETE FROM items WHERE id = ? AND owner_id = ?",
            (item_id, user_id),
        )
    if result.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found.")
