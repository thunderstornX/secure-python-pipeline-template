from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from app.config import settings
from app.database import init_db
from app.routes import users, items


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    description=(
        "Reference FastAPI application demonstrating the four secure-python-pipeline "
        "patterns: parameterised SQL, environment-sourced secrets, Pydantic input "
        "validation, and bcrypt password hashing."
    ),
    version="1.0.0",
    debug=settings.debug,
    lifespan=lifespan,
)

app.include_router(users.router)
app.include_router(items.router)


@app.get("/healthz", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok"}
