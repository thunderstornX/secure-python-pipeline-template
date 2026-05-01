from pydantic import BaseModel, EmailStr, Field, field_validator
import re


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("password must contain at least one digit")
        return v


class UserResponse(BaseModel):
    id: int
    username: str
    email: str

    model_config = {"from_attributes": True}


class ItemCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    price: float = Field(gt=0, le=1_000_000)


class ItemResponse(BaseModel):
    id: int
    name: str
    description: str
    price: float
    owner_id: int

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
