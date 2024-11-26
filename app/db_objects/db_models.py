"""This module contains the SQLAlchemy models for the application."""
import json
from sqlalchemy import JSON, Boolean, Column, ForeignKey, Integer, PickleType, String, Table
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.utils import generate_timestamp, generate_uuid
from app.db_objects._base import Base
# from app.core.config import settings

# pylint: disable=R0903


# Many-to-Many Reference Tables
# blocked_users_table = Table(
#     "blocked_users",
#     Base.metadata,
#     Column("user_uuid", ForeignKey("users.uuid")),
#     Column("blocked_user_uuid", ForeignKey("users.uuid"))
# )


users_files_links = Table(
    "users_files_links",
    Base.metadata,
    Column("user_uuid", ForeignKey("users.uuid")),
    Column("file_id", ForeignKey("files.id")),
)

# ---- MODELS ----


class File(Base):
    """Files model."""
    __tablename__ = "files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_name: Mapped[str] = mapped_column(unique=True)
    file_type: Mapped[str]
    file_path: Mapped[str]
    description: Mapped[str | None]
    created_at: Mapped[int] = mapped_column(
        Integer,
        default=generate_timestamp
    )

    # Relationships
    #   One-to-One
    created_by_uuid: Mapped[str] = mapped_column(
        String, ForeignKey('users.uuid'))
    created_by: Mapped["User"] = relationship(
        "User", foreign_keys=[created_by_uuid])

    def __repr__(self) -> str:
        repr_dict = {
            "file_name": self.file_name,
            "file_type": self.file_type,
            "created_at": self.created_at,
        }
        return f"File({json.dumps(repr_dict, indent=4)})"


class OAuthToken(Base):
    """OAuth2 tokens model."""
    __tablename__ = "oauth_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    oauth_version: Mapped[str] = mapped_column(String(1))
    provider: Mapped[str] = mapped_column(String(40))
    # OAuth1
    oauth_token: Mapped[str | None]
    oauth_token_secret: Mapped[str | None]
    # OAuth2
    token_type: Mapped[str | None] = mapped_column(String(40))
    access_token: Mapped[str | None]
    refresh_token: Mapped[str | None]
    expires_at: Mapped[int | None]

    # Foreign keys
    user_uuid: Mapped[str] = mapped_column(String, ForeignKey('users.uuid'))

    def __repr__(self) -> str:
        repr_dict = {
            "OAuthVersion": self.oauth_version,
            "provider": self.provider,
            "expires_at": self.expires_at,
        }
        return f"OAuthToken({json.dumps(repr_dict, indent=4)})"


class ExternalAccount(Base):
    """External Accounts model."""
    __tablename__ = "external_accounts"

    provider: Mapped[str]
    external_account_id: Mapped[str] = mapped_column(String, primary_key=True)
    username: Mapped[str | None]
    display_name: Mapped[str | None]
    email: Mapped[str | None]
    picture_url: Mapped[str | None]

    # Foreign keys
    user_uuid: Mapped[str] = mapped_column(String, ForeignKey('users.uuid'))

    def __repr__(self) -> str:
        repr_dict = {
            "provider": self.provider,
            "external_account_id": self.external_account_id,
            "username": self.username,
            "display_name": self.display_name,
            "email": self.email,
            "picture_url": self.picture_url,
            "user_uuid": self.user_uuid
        }
        return f"ExternalAccount({json.dumps(repr_dict, indent=4)})"


# pylint: disable=E1136


class User(Base):
    """Users model."""
    __tablename__ = "users"

    uuid: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid
    )
    username: Mapped[str] = mapped_column(
        String,
        nullable=False,
        unique=True
    )
    display_name: Mapped[str] = mapped_column(
        String,
        nullable=False
    )
    email: Mapped[str] = mapped_column(
        String,
        nullable=False,
        unique=True
    )
    email_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False
    )
    hashed_password: Mapped[str] = mapped_column(
        String,
        nullable=False
    )
    otp_method: Mapped[bool] = mapped_column(
        String,
        default="none"
    )
    otp_secret: Mapped[str | None]
    roles: Mapped[str] = mapped_column(
        MutableList.as_mutable(JSON),
        default=["user"]
    )
    description: Mapped[str | None]
    created_at: Mapped[int] = mapped_column(
        Integer,
        default=generate_timestamp
    )
    updated_at: Mapped[int] = mapped_column(
        Integer,
        default=generate_timestamp
    )
    is_external_only: Mapped[bool] = mapped_column(
        Boolean,
        default=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True
    )
    deactivated_reason: Mapped[str | None]

    # Relationships

    #   One-to-One
    profile_picture_id: Mapped[str | None] = mapped_column(
        Integer,
        ForeignKey('files.id'),
    )
    profile_picture: Mapped["File | None"] = relationship(
        "File", foreign_keys=[profile_picture_id])

    #   One-to-Many
    external_accounts: Mapped[list["ExternalAccount"]] = relationship(
        "ExternalAccount",
        cascade="all, delete",
    )
    oauth_tokens: Mapped[list["OAuthToken"]] = relationship(
        "OAuthToken",
        cascade="all, delete",
    )

    blocked_uuids: Mapped[str] = mapped_column(
        MutableList.as_mutable(JSON),
        default=list
    )

    #   Many-to-One

    #   Many-to-Many
    files: Mapped[list["File"]] = relationship(
        "File",
        secondary="users_files_links",
        viewonly=True
    )

    def __repr__(self) -> str:
        repr_dict = {
            "uuid": self.uuid,
            "username": self.username,
            "display_name": self.display_name,
            "email": self.email,
            "roles": self.roles,
            "blocked_uuids": self.blocked_uuids
        }
        return f"User({json.dumps(repr_dict, indent=4)})"
