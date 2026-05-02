"""
User CRUD + login.  Demonstrates:

- Parameterised SQL (no f-strings into execute())
- bcrypt password hashing with a configurable cost factor
- TOCTOU-safe insertion via UNIQUE-constraint exception handling
- Constant-time bcrypt verification on login (no early-exit on missing user)
"""

from __future__ import annotations

import sqlite3

import bcrypt
from fastapi import APIRouter, HTTPException, status

from app.auth import issue_token
from app.config import settings
from app.database import get_db
from app.models import (
    LoginRequest,
    LoginResponse,
    UserCreate,
    UserResponse,
)

router = APIRouter(prefix="/users", tags=["users"])

# A pre-computed bcrypt hash of a fixed nonce, used to equalise login
# timing when a username does not exist (defends against user enumeration).
# bcrypt rejects NUL bytes in the password, so we use a printable nonce.
_DUMMY_HASH = bcrypt.hashpw(b"timing-equaliser-nonce", bcrypt.gensalt(rounds=4)).decode()


def _hash_password(plain: str) -> str:
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(plain.encode(), salt).decode()


def _verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate) -> UserResponse:
    pw_hash = _hash_password(payload.password)
    with get_db() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, email, pw_hash) VALUES (?, ?, ?)",
                (payload.username, str(payload.email), pw_hash),
            )
        except sqlite3.IntegrityError as exc:
            # UNIQUE constraint (username or email already taken). The DB
            # check is the canonical race-free dedup; we never SELECT-then-INSERT.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email already registered.",
            ) from exc
        user_id = cursor.lastrowid
    return UserResponse(id=user_id, username=payload.username, email=str(payload.email))


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, pw_hash FROM users WHERE username = ?",
            (payload.username,),
        ).fetchone()

    # Always run bcrypt.checkpw, even on missing user, to defeat timing
    # enumeration. The dummy hash never matches a real password.
    stored_hash = row["pw_hash"] if row else _DUMMY_HASH
    if not _verify_password(payload.password, stored_hash) or row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
        )

    return LoginResponse(access_token=issue_token(row["id"]))


@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int) -> UserResponse:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, username, email FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return UserResponse(id=row["id"], username=row["username"], email=row["email"])


@router.get("/", response_model=list[UserResponse])
def list_users(limit: int = 20, offset: int = 0) -> list[UserResponse]:
    limit = min(max(limit, 1), 100)
    offset = max(offset, 0)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, email FROM users LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [UserResponse(id=r["id"], username=r["username"], email=r["email"]) for r in rows]
