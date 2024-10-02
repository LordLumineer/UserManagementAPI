from math import e
import os
from pydantic import BaseModel, Field, computed_field

from app.core.config import settings


class FileBase(BaseModel):
    description: str | None = Field(
        max_length=256,
        default=None
    )


class FileReadDB(BaseModel):
    id: int
    file_name: str
    file_type: str
    file_path: str = Field(exclude=True)
    created_at: int
    created_by: str

    class Config:
        """ORM model configuration"""
        orm_mode = True


class FileRead(FileReadDB):
    @computed_field
    def file_url(self) -> str:
        return f"{settings.BASE_URL}{settings.API_STR}/files/{self.id}/file"


class FileCreate(FileBase):
    file_name: str
    created_by: str

    @computed_field
    def file_type(self) -> str:
        return os.path.splitext(self.file_name)[1]

    @computed_field
    def file_path(self) -> str:
        return os.path.join("..", "data", self.file_name)


class FileUpdate(FileBase):
    pass
