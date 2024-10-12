"""
File object operations.

This module contains the functions to create, read, update and delete files
from the database and filesystem.

@file: ./app/core/object/file.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from fastapi import UploadFile
from fastapi.exceptions import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.utils import remove_file
from app.templates.models import File as File_Model
from app.templates.models import users_files_links
from app.templates.schemas.file import FileCreate, FileReadDB, FileUpdate


def get_nb_files(db: Session) -> int:
    """
    Get the number of files in the database.

    :param Session db: The current database session.
    :return int: The number of files.
    """
    return db.query(File_Model).count()


def get_files(db: Session, skip: int = 0, limit: int = 100) -> list[FileReadDB]:
    """
    Get a list of files from the database.

    :param Session db: The current database session.
    :param int skip: The number of items to skip (default is 0).
    :param int limit: The maximum number of items to return (default is 100).
    :return list[FileReadDB]: A list of file objects.
    """

    return db.query(File_Model).offset(skip).limit(limit).all()


def get_file(db: Session, file_id: int) -> File_Model:
    """
    Get a file by its ID.

    :param Session db: The current database session.
    :param int file_id: The ID of the file to get.
    :return File_Model: The file object.
    :raises HTTPException: If the file is not found.
    """
    db_file = db.query(File_Model).filter(File_Model.id == file_id).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    return db_file


async def create_file(db: Session, new_file: FileCreate, file: UploadFile) -> File_Model:
    """
    Create a new file in the database and save the file to the filesystem.

    :param Session db: The current database session.
    :param FileCreate new_file: The file object to create.
    :param UploadFile file: The file to upload.
    :return File_Model: The new file object.
    :raises HTTPException: If there is an error creating the file.
    """
    from app.core.object.user import link_file_to_user  # pylint: disable=import-outside-toplevel
    with open(new_file.file_path, "wb") as f:
        f.write(file.file.read())
    new_db_file = File_Model(**new_file.model_dump())
    try:
        db.add(new_db_file)
        db.commit()
        db.refresh(new_db_file)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    link_file_to_user(db, new_file.created_by, new_db_file.id)
    return new_db_file


def update_file(db: Session, file_id: int, file: FileUpdate) -> File_Model:
    """
    Update a file by its ID.

    :param Session db: The current database session.
    :param int file_id: The ID of the file to update.
    :param FileUpdate file: The file object with the updated data.
    :return File_Model: The updated file object.
    :raises HTTPException: If there is an error updating the file.
    """
    db_file = get_file(db, file_id)
    file_data = file.model_dump(exclude_unset=True, exclude_none=True)
    for field, value in file_data.items():
        setattr(db_file, field, value)
    try:
        db.add(db_file)
        db.commit()
        db.refresh(db_file)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    return db_file


def delete_file(db: Session, file_id: int) -> bool:
    """
    Delete a file by its ID.

    :param Session db: The current database session.
    :param int file_id: The ID of the file to delete.
    :return bool: True if the file is deleted successfully, False otherwise.
    :raises HTTPException: If there is an error deleting the file.
    """
    db_file = get_file(db, file_id)
    db.delete(db_file)

    # delete from links
    db.execute(delete(users_files_links).where(
        users_files_links.c.file_id == file_id
    ))
    # ... other links related to the file

    # delete file from disk
    try:
        remove_file(db_file.file_path)
        db.commit()
    except OSError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete file. {
                            e.strerror}") from e
    return True


# ----- Helper functions ----- #


def get_files_list(db: Session, id_list: list[int]) -> list[File_Model]:
    """
    Get a list of files from the database based on their IDs.

    :param Session db: The current database session.
    :param list[int] id_list: A list of file IDs.
    :return list[File_Model]: A list of file objects.
    """

    return db.query(File_Model).filter(File_Model.id.in_(id_list)).all()


def get_file_users_uuid(db: Session, file_id: int) -> list[str]:
    """
    Get a list of UUIDs of users who have access to the specified file.

    :param Session db: The current database session.
    :param int file_id: The ID of the file.
    :return list[str]: A list of UUIDs of users who have access to the file.
    """
    stmt = select(users_files_links.c.user_uuid).where(
        users_files_links.c.file_id == file_id)
    result = db.execute(stmt)
    return [row[0] for row in result]
