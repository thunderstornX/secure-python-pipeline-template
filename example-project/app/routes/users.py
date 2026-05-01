import bcrypt
from fastapi import APIRouter, HTTPException, status
from app.models import UserCreate, UserResponse
from app.database import get_db
from app.config import settings

router = APIRouter(prefix="/users", tags=["users"])


def _hash_password(plain: str) -> str:
    # bcrypt with configurable cost factor — never MD5/SHA1
    salt = bcrypt.gensalt(rounds=settings.bcrypt_rounds)
    return bcrypt.hashpw(plain.encode(), salt).decode()


def _verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate) -> UserResponse:
    pw_hash = _hash_password(payload.password)
    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (payload.username, payload.email),
        ).fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email already registered.",
            )
        cursor = conn.execute(
            # Parameterised query — never an f-string here
            "INSERT INTO users (username, email, pw_hash) VALUES (?, ?, ?)",
            (payload.username, str(payload.email), pw_hash),
        )
        user_id = cursor.lastrowid
    return UserResponse(id=user_id, username=payload.username, email=str(payload.email))


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
    limit = min(max(limit, 1), 100)  # clamp; never trust raw caller value
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, email FROM users LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [UserResponse(id=r["id"], username=r["username"], email=r["email"]) for r in rows]
