"""
This module contains the pydantic models for the users of the application.
The models include the UserCreate, UserRead, UserReadDB, UserUpdate and UserReadWithFiles models.
"""
from datetime import datetime, timezone
from typing import Literal, Self
from fastapi.exceptions import HTTPException
from pydantic import BaseModel, ConfigDict, computed_field, Field, field_validator, model_validator

from app.core.config import settings
from app.core.db import get_async_db, get_sync_db
from app.db_objects.db_models import User as User_DB
from app.core.permissions import UserRole
from app.core.utils import generate_random_letters, validate_email, validate_password, validate_username
from app.core.security import hash_password
from app.templates.schemas.file import FileReadDB
from app.templates.schemas.external_account import ExternalAccountBase

# pylint: disable=R0903


class UserHistory(BaseModel):
    """History of user actions."""
    time: str = Field(default_factory=lambda: datetime.now(
        timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z'))
    action: str
    description: str
    by: str


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
    roles: list[UserRole] = Field(default=["user"])
    description: str | None = Field(
        default=None,
        max_length=256
    )
    profile_picture_id: int | None = None
    is_external_only: bool = Field(
        default=False
    )
    is_active: bool = Field(
        default=True
    )

    blocked_uuids: list[str] = Field(default=[])

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
    profile_picture_id: int | None = Field(exclude=True)
    profile_picture: FileReadDB | None
    created_at: int
    updated_at: int
    user_history: list[UserHistory] = Field(default=[])

    model_config = ConfigDict(from_attributes=True)


class UserRead(UserReadDB):
    """Model for a user in the API."""
    @computed_field
    def picture_url(self) -> str:
        """The URL of the user's profile picture."""
        return f"{settings.BASE_URL}{settings.API_STR}/user/{self.uuid}/image"

    # @computed_field
    # def external_accounts(self) -> list[ExternalAccountBase]:
    #     """A list of third-party accounts associated with the user."""
    #     from app.db_objects.user import get_sync_user   # pylint: disable=import-outside-toplevel
    #     db = next(get_sync_db())
    #     try:
    #         return get_sync_user(db, self.uuid, raise_error=False).external_accounts
    #     finally:
    #         db.close()

    # @computed_field
    # def files(self) -> list[FileReadDB]:
    #     """A list of files associated with the user."""
    #     from app.db_objects.user import get_sync_user   # pylint: disable=import-outside-toplevel
    #     db = next(get_sync_db())
    #     try:
    #         return get_sync_user(db, self.uuid, raise_error=False).files
    #     finally:
    #         db.close()

    # @computed_field
    # def external_accounts(self) -> list[ExternalAccountBase]:
    #     """A list of third-party accounts associated with the user."""
    #     from sqlalchemy.orm import joinedload
    #     from app.db_objects.db_models import File as File_DB
    #     db = next(get_sync_db())
    #     try:
    #         db_user = db.query(User_DB).filter(User_DB.uuid == self.uuid).options(
    #             joinedload(User_DB.profile_picture).joinedload(File_DB.created_by)
    #         ).first()
    #         return db_user.external_accounts
    #     finally:
    #         db.close()

    # @computed_field
    # async def external_accounts(self) -> list[ExternalAccountBase]:
    #     """A list of third-party accounts associated with the user."""
    #     from app.db_objects.user import get_user   # pylint: disable=import-outside-toplevel
    #     db = await get_async_db().__anext__()
    #     try:
    #         return await get_user(db, self.uuid, raise_error=False).external_accounts
    #     finally:
    #         await db.close()

    # @computed_field
    # def files(self) -> list[FileReadDB]:
    #     """A list of files associated with the user."""
    #     from sqlalchemy.orm import joinedload
    #     from app.db_objects.db_models import File as File_DB
    #     db = next(get_sync_db())
    #     try:
    #         db_user = db.query(User_DB).filter(User_DB.uuid == self.uuid).options(
    #             joinedload(User_DB.profile_picture).joinedload(File_DB.created_by)
    #         ).first()
    #         return db_user.files
    #     finally:
    #         db.close()

    # @computed_field
    # async def files(self) -> list[FileReadDB]:
    #     """A list of files associated with the user."""
    #     from app.db_objects.user import get_user   # pylint: disable=import-outside-toplevel
    #     db = await get_async_db().__anext__()
    #     try:
    #         return await get_user(db, self.uuid, raise_error=False).files
    #     finally:
    #         await db.close()


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
    # otp_method: Literal["none", "authenticator",
    #                     "email"] | None = Field(default=None, exclude=True)
    # otp_secret: str | None = Field(default=None, exclude=True)
    # permission: Literal["user", "manager", "admin"] | None = None
    roles: list[UserRole] | None = None
    is_external_only: bool | None = None
    isActive: bool | None = None
    blocked_uuids: list[str] | None = None
    action: UserHistory | None = None

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
