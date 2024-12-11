"""This module contains functions for CRUD operations on files."""
import os
import aiofiles
from fastapi import UploadFile
from fastapi.exceptions import HTTPException
from sqlalchemy import delete, insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.utils import remove_file
from app.db_objects.db_models import File as File_DB
from app.db_objects.db_models import User as User_DB
from app.db_objects.db_models import users_files_links
from app.templates.schemas.file import FileCreate, FileReadDB, FileUpdate

# ~~~~~ CRUD ~~~~~ #


# ------- Create ------- #


async def create_file(db: AsyncSession, new_file: FileCreate, file: UploadFile) -> File_DB:
    """
    Create a new file in the database and link it to a user.

    :param Session db: The database session.
    :param FileCreate new_file: The FileCreate object containing metadata for the new file.
    :param UploadFile file: The file to be uploaded.
    :return File_DB: The database representation of the newly created file.
    :raises HTTPException: If there is an integrity error during the database operation.
    """
    async with aiofiles.open(new_file.file_path, "wb") as f:
        await f.write(await file.read())
    db_file = File_DB(**new_file.model_dump())
    db_file.file_name = os.path.basename(new_file.file_name)
    db.add(db_file)
    await db.commit()
    await db.refresh(db_file)
    # Link User to File
    await db.execute(
        insert(users_files_links).values(
            user_uuid=db_file.created_by_uuid,
            file_id=db_file.id
        )
    )
    await db.commit()
    return db_file


# ------- Read ------- #


async def get_file(db: AsyncSession, file_id: int, raise_error: bool = True) -> File_DB:
    """
    Get a file by its ID.

    :param Session db: The database session.
    :param int file_id: The ID of the file to get.
    :param bool raise_error: If True, raises an HTTPException if the file is not found.
    :return File_DB: The file object.
    :raises HTTPException: If the file is not found and `raise_error` is `True`.
    """
    result = await db.execute(select(File_DB).filter(File_DB.id == file_id))
    db_file = result.unique().scalar()
    if not db_file and raise_error:
        raise HTTPException(status_code=404, detail="File not found")
    return db_file


async def get_files(db: AsyncSession, skip: int = 0, limit: int = 100) -> list[FileReadDB]:
    """
    Get a list of files with pagination.

    :param Session db: The database session.
    :param int skip: The number of items to skip (default is 0).
    :param int limit: The maximum number of items to return (default is 100).
    :return list[FileReadDB]: A list of file objects.
    """
    result = await db.execute(
        select(File_DB).offset(skip).limit(limit)
    )
    return result.unique().scalars().all()


async def get_nb_files(db: AsyncSession) -> int:
    """
    Get the number of files.

    :param Session db: The database session.
    :return int: The number of files.
    """
    result = await db.execute(text(f"SELECT COUNT(*) FROM {File_DB.__tablename__}"))
    return int(result.unique().scalar())


async def get_files_list(db: AsyncSession, external_account_id_list: list[int]) -> list[File_DB]:
    """
    Get a list of files from their IDs.

    This function retrieves a list of files from the database, based on their IDs.

    :param Session db: The current database session.
    :param list[int] external_account_id_list: The IDs of the files to get.
    :return list[File_DB]: A list of file model objects.
    """
    result = await db.execute(select(File_DB).where(File_DB.id.in_(external_account_id_list)))
    return result.unique().scalars().all()


# ------- Update ------- #


async def update_file(db: AsyncSession, db_file: File_DB, new_file: FileUpdate) -> File_DB:
    """
    Update a file in the database.

    This function updates a file in the database with the values provided in the new_file object.
    The function returns the updated file object.

    :param Session db: The database session.
    :param File_DB db_file: The file object to update.
    :param FileUpdate new_file: The new values for the file.
    :return File_DB: The updated file object.
    """
    file_data = new_file.model_dump(exclude_unset=True, exclude_none=True)
    for field, value in file_data.items():
        setattr(db_file, field, value)
    db.add(db_file)
    await db.commit()
    await db.refresh(db_file)
    return db_file


# ------- Delete ------- #


async def delete_file(db: AsyncSession, file: File_DB) -> bool:
    # delete from links
    """
    Delete a file from the database and from disk.

    This function deletes a file from the database and from disk.
    It returns a boolean indicating whether the operation was successful.

    :param Session db: The current database session.
    :param File_DB file: The file object to delete.
    :return bool: True if the operation was successful.
    """
    result = await db.execute(
        select(users_files_links.c.user_uuid).where(
            users_files_links.c.file_id == file.id
        )
    )
    files = result.unique().scalars().all()
    if files:
        await db.execute(
            delete(users_files_links).where(
                users_files_links.c.file_id == file.id
            )
        )
    # ... other links related to the file
    await db.delete(file)

    # delete file from disk
    try:
        remove_file(file.file_path)
        await db.commit()
    except OSError as e:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete file. {e.strerror}"
        ) from e
    return True


# ----- Helper functions ----- #


async def get_file_users(db: AsyncSession, file: File_DB) -> list[User_DB]:
    """
    Get a list of users who are related to a file.

    :param Session db: The current database session.
    :param File_DB file: The file object.
    :return list[User_DB]: A list of user objects.
    """
    result = await db.execute(select(users_files_links.c.user_uuid).where(
        users_files_links.c.file_id == file.id))
    result = await db.execute(select(User_DB).where(User_DB.uuid.in_([row[0] for row in result])))
    return result.unique().scalars().all()


async def link_file_user(db: AsyncSession, db_user: User_DB, db_file: File_DB) -> File_DB:
    """
    Link a file to a user.

    This function links a file to a user by adding the necessary entries to the
    users_files_links table.

    :param Session db: The current database session.
    :param User_DB db_user: The user object.
    :param File_DB db_file: The file object.
    :return File_DB: The updated file object.
    """
    await db.execute(
        insert(users_files_links).values(
            user_uuid=db_user.uuid, file_id=db_file.id)
    )
    await db.commit()
    return db_file
