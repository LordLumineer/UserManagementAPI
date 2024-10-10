from typing import Literal
from fastapi import HTTPException
from pydantic import BaseModel, Field, computed_field, field_validator

from app.core.object.file import get_files_list
from app.core.config import settings
from app.core.db import get_db
from app.core.utils import validate_email, validate_password, validate_username
from app.core.security import hash_password
from app.templates.schemas.file import FileReadDB

# pylint: disable=R0903


class UserBase(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=32
    )
    email: str  # EmailStr
    otp_method: Literal["none", "authenticator", "email"] = Field(
        default="none"
    )
    permission: Literal["user", "manager", "admin"] = Field(
        default="user",
    )
    description: str | None = Field(
        default=None,
        max_length=256
    )
    profile_picture_id: int | None = None
    is_active: bool = Field(
        default=True
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        return validate_username(value)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return validate_email(value)

    @field_validator("otp_method")
    @classmethod
    def validate_otp_method(cls, value: str) -> str:
        if settings.EMAIL_METHOD == "none" and value == "email":
            raise ValueError("No EMAIL Method set")
        return value


class UserReadDB(UserBase):
    uuid: str
    email_verified: bool
    hashed_password: str = Field(exclude=True)
    otp_secret: str | None = Field(exclude=True)
    profile_picture_id: int | None
    created_at: int
    updated_at: int

    @computed_field
    def files_id(self) -> list[int]:
        from app.core.object.user import get_user_files_id   # pylint: disable=import-outside-toplevel
        db = next(get_db())
        try:
            files_id_list = get_user_files_id(db, self.uuid)
        finally:
            db.close()
        return files_id_list


    class Config:
        """ORM model configuration"""
        from_attributes = True


class UserRead(UserReadDB):
    @computed_field
    def picture_url(self) -> str:
        return f"{settings.BASE_URL}{settings.API_STR}/users/{self.uuid}/image"

    @computed_field
    def files(self) -> list[FileReadDB]:
        db = next(get_db())
        try:
            files_list = get_files_list(db, self.files_id)
        finally:
            db.close()
        return files_list


class UserCreate(UserBase):
    email_verified: bool = Field(default=False)
    password: str = Field(exclude=True)

    @field_validator("password")
    @classmethod
    def password_validation(cls, value: str) -> str:
        return validate_password(value)

    @computed_field
    def hashed_password(self) -> str:
        return hash_password(self.password)


class UserUpdate(UserBase):
    username: str | None = None
    email: str | None = None
    email_verified: bool | None = None
    password: str | None = None
    otp_method: Literal["none", "authenticator", "email"] | None = None
    otp_secret: str | None = None
    permission: Literal["user", "manager", "admin"] | None = None
    isActive: bool | None = None

    @field_validator('password')
    @classmethod
    def password_validation(cls, v):
        if v is not None:
            return validate_password(v)
        return v

    @computed_field
    def hashed_password(self) -> str:
        return hash_password(self.password) if self.password else None
