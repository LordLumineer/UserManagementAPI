"""
Pydantic models for the File objects.

@file: ./app/templates/schemas/file.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
import os
from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.core.config import settings

# pylint: disable=R0903


class FileBase(BaseModel):
    """Base class for File models."""
    description: str | None = Field(
        max_length=256,
        default=None
    )


class FileReadDB(FileBase):
    """File model for database read operations."""
    id: int
    file_name: str
    file_type: str
    file_path: str = Field(exclude=True)
    created_at: int
    created_by_uuid: str

    model_config = ConfigDict(from_attributes=True)


class FileRead(FileReadDB):
    """File model for API read operations."""
    @computed_field
    def file_url(self) -> str:
        """URL of the file content."""
        return f"{settings.BASE_URL}{settings.API_STR}/files/{self.id}/file"


class FileCreate(FileBase):
    """File model for create operations."""
    file_name: str
    created_by_uuid: str

    @computed_field
    def file_type(self) -> str:
        """Get the file type from the file name."""
        return self.file_name.split('.')[-1].lower()

    @computed_field
    def file_path(self) -> str:
        """Path of the file on the filesystem."""
        return os.path.join("..", "data", "files", self.file_name)


class FileUpdate(FileBase):
    """File model for update operations."""
