"""
This module contains the pydantic models for the users of the application.
The models include the UserCreate, UserRead, UserReadDB, UserUpdate and UserReadWithFiles models.

@file: ./app/templates/schemas/user.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from typing import Literal, Self
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, computed_field, Field, field_validator, model_validator

from app.core.object.third_party_account import get_third_party_accounts_list
from app.core.object.file import get_files_list
from app.core.config import settings
from app.core.db import get_db
from app.core.utils import generate_random_letters, validate_email, validate_password, validate_username
from app.core.security import hash_password
from app.templates.schemas.file import FileReadDB
from app.templates.schemas.third_party_account import ThirdPartyAccountBase

# pylint: disable=R0903


class UserBase(BaseModel):
    """Base model for user creation."""
    username: str = Field(
        min_length=1,
        max_length=32
    )
    display_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=32
    )
    email: str  # EmailStr
    otp_method: Literal["none", None, "authenticator", "email"] = Field(
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
    is_third_part_only: bool = Field(
        default=False
    )
    is_active: bool = Field(
        default=True
    )

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        return validate_username(value)

    @model_validator(mode="after")
    def _validate_display_name(self) -> Self:
        if self.display_name is None:
            self.display_name = self.username
            return self
        if str(self.display_name).replace(" ", "_").lower() == self.username:
            return self
        raise HTTPException(
            status_code=400,
            detail="The display name must be the same as the username. "
            "Capitalization allowed. Spaces are only allowed in place of underscores."
        )

    @field_validator("email")
    @classmethod
    def _email_validation(cls, value: str) -> str:
        return validate_email(value)

    @field_validator("otp_method")
    @classmethod
    def _validate_otp_method(cls, value: str) -> str:
        if settings.EMAIL_METHOD == "none" and value == "email":
            raise ValueError("No EMAIL Method set")
        return value


class UserReadDB(UserBase):
    """Model for a user in the database."""
    uuid: str
    email_verified: bool
    hashed_password: str = Field(exclude=True)
    otp_secret: str | None = Field(exclude=True)
    profile_picture_id: int | None
    created_at: int
    updated_at: int

    @computed_field
    def third_party_account_ids(self) -> list[int]:
        """A list of third party account IDs associated with the user."""
        from app.core.object.user import get_user_third_party_account_ids   # pylint: disable=import-outside-toplevel
        db = next(get_db())
        try:
            third_party_account_ids_list = get_user_third_party_account_ids(
                db, self.uuid)
        finally:
            db.close()
        return third_party_account_ids_list

    @computed_field
    def files_id(self) -> list[int]:
        """A list of file IDs associated with the user."""
        from app.core.object.user import get_user_files_ids   # pylint: disable=import-outside-toplevel
        db = next(get_db())
        try:
            files_id_list = get_user_files_ids(db, self.uuid)
        finally:
            db.close()
        return files_id_list

    class Config:
        """ORM model configuration"""
        from_attributes = True


class UserRead(UserReadDB):
    """Model for a user in the API."""
    @computed_field
    def picture_url(self) -> str:
        """The URL of the user's profile picture."""
        return f"{settings.BASE_URL}{settings.API_STR}/user/{self.uuid}/image"

    @computed_field
    def third_party_accounts(self) -> list[ThirdPartyAccountBase]:
        """A list of third-party accounts associated with the user."""
        db = next(get_db())
        try:
            third_party_accounts_list = get_third_party_accounts_list(
                db, self.third_party_account_ids)
        finally:
            db.close()
        return third_party_accounts_list

    @computed_field
    def files(self) -> list[FileReadDB]:
        """A list of files associated with the user."""
        db = next(get_db())
        try:
            files_list = get_files_list(db, self.files_id)
        finally:
            db.close()
        return files_list


class UserCreate(UserBase):
    """Model for creating a new user."""
    email_verified: bool = Field(default=False)
    password: str = Field(exclude=True)

    @field_validator("password")
    @classmethod
    def _password_validation(cls, value: str) -> str:
        return validate_password(value)

    @computed_field
    def hashed_password(self) -> str:
        """The hashed password of the user."""
        return hash_password(self.password)

    @computed_field
    def otp_secret(self) -> str:
        """The OTP secret of the user."""
        return generate_random_letters(length=32, seed=self.username)


class UserUpdate(UserBase):
    """Model for updating an existing user."""
    username: str | None = None
    email: str | None = None
    email_verified: bool | None = None
    password: str | None = None
    # otp_method change done in a specific endpoint
    otp_method: Literal["none", "authenticator",
                        "email"] | None = Field(default="none", exclude=True)
    permission: Literal["user", "manager", "admin"] | None = None
    is_third_part_only: bool | None = None
    isActive: bool | None = None

    @field_validator('password')
    @classmethod
    def _password_validation(cls, v):
        if v is not None:
            return validate_password(v)
        return v

    @computed_field
    def hashed_password(self) -> str:
        """The hashed password of the user if provided, otherwise None."""
        return hash_password(self.password) if self.password else None
