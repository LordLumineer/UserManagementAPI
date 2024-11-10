"""This module contains the SQLAlchemy models for the application."""
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.utils import generate_timestamp, generate_uuid
from app.db_objects._base import Base
# from app.core.config import settings

# pylint: disable=R0903


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

    # Foreign keys
    created_by: Mapped[str] = mapped_column(String, ForeignKey('users.uuid'))


class OAuthToken(Base):
    """OAuth2 tokens model."""
    __tablename__ = "oauth_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    oauth_version: Mapped[str] = mapped_column(String(1))
    name: Mapped[str] = mapped_column(String(40))
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


class ExternalAccount(Base):
    """External Accounts model."""
    __tablename__ = "external_accounts"

    external_account_id: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str]

    # Foreign keys
    user_uuid: Mapped[str] = mapped_column(String, ForeignKey('users.uuid'))


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

    permission: Mapped[str] = mapped_column(
        String,
        default="user"
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

    # Foreign keys
    profile_picture_id: Mapped[str | None] = mapped_column(
        Integer,
        ForeignKey('files.id'),
    )

    # Relationships
    #   One-to-many
    external_accounts: Mapped[list[ExternalAccount]] = relationship(
        "ExternalAccount",
        cascade="all, delete",
    )
    oauth_tokens: Mapped[list[OAuthToken]] = relationship(
        "OAuthToken",
        cascade="all, delete",
    )
    #   Many-to-many
    files: Mapped[list[File]] = relationship(
        "File",
        secondary="users_files_links",
        viewonly=True
    )


# Many-to-many


users_files_links = Table(
    "users_files_links",
    Base.metadata,
    Column("user_uuid", ForeignKey("users.uuid")),
    Column("file_id", ForeignKey("files.id")),
)
