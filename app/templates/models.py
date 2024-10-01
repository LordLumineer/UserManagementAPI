import time
import uuid

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.base import Base
# from app.core.config import settings

# pylint: disable=R0903


class User(Base):
    """Users model."""
    __tablename__ = "users"

    uuid: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(
        String,
        nullable=False,
        unique=True
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
    permition: Mapped[str] = mapped_column(
        String,
        default="user"
    )
    description: Mapped[str | None]
    created_at: Mapped[int] = mapped_column(
        Integer,
        default=int(time.time())
    )
    updated_at: Mapped[int] = mapped_column(
        Integer,
        default=int(time.time())
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
    files_id: Mapped[list[int]] = relationship(
        "File",
        secondary="users_files_links",
        viewonly=True
    )


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
        default=int(time.time())
    )

    # Foreign keys
    created_by: Mapped[str] = mapped_column(String, ForeignKey('users.uuid'))


users_files_links = Table(
    "users_files_links",
    Base.metadata,
    Column("user_uuid", ForeignKey("users.uuid")),
    Column("file_id", ForeignKey("files.id")),
)
