"""This module contains the API endpoints related to the files (e.g. upload, download, delete, update)."""
from fastapi import APIRouter, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.params import Depends, File, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.permissions import has_permission
from app.db_objects.file import (
    create_file, update_file, delete_file,
    get_file, get_files, get_files_list, get_nb_files
)
from app.db_objects.user import get_current_user
from app.db_objects.db_models import User as User_DB
from app.templates.schemas.file import FileCreate, FileRead, FileReadDB, FileUpdate


router = APIRouter()

# ~~~~~ CRUD ~~~~~ #
# ------- Create ------- #


@router.post("/", response_model=FileReadDB)
def new_file(
    description: str | None = Query(default=None),
    file: UploadFile = File(...),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new file.

    Parameters
    ----------
    description : str, optional
        The description for the file (default is None).
    file : UploadFile
        The file to upload.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    FileReadDB
        The new file object.
    """
    has_permission(current_user, "file", "create")
    return create_file(
        db,
        FileCreate(
            description=description,
            file_name=file.filename,
            created_by_uuid=current_user.uuid
        ),
        file
    )

# ------- Read ------- #


@router.get("/", response_model=list[FileReadDB])
def read_files(
    skip: int = Query(default=0), limit: int = Query(default=100),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a list of files

    Parameters
    ----------
    skip : int, optional
        The number of items to skip (default is 0).
    limit : int, optional
        The maximum number of items to return (default is 100).
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    list[FileReadDB]
        A list of file objects.
    """
    has_permission(current_user, "file", "read")
    return get_files(db, skip=skip, limit=limit)


@router.get("/files", response_model=list[FileRead])
def read_files_list(
    files_ids: list[int] = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a list of files based on their IDs

    Parameters
    ----------
    files_ids : list[int], optional
        The IDs of the files to get (default is an empty list).
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    list[FileReadDB]
        A list of file objects.
    """
    has_permission(current_user, "file", "read")
    return get_files_list(db, files_ids)


@router.get("/count", response_model=int)
def read_files_number(
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the number of files.

    Parameters
    ----------
    db : Session
        The current database session.

    Returns
    -------
    int
        The number of files.
    """
    has_permission(current_user, "file", "read")
    return get_nb_files(db)


@router.get("/{file_id}", response_model=FileRead)
def read_file(
    file_id: int,
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a file by its ID.

    Parameters
    ----------
    file_id : int
        The ID of the file to get.
    db : Session
        The current database session.

    Returns
    -------
    FileRead
        The file object.
    """
    # return get_file(db, file_id)
    file = get_file(db, file_id)
    has_permission(current_user, "file", "read", file)
    return file


@router.get("/{file_id}/file", response_class=FileResponse)
def read_file_file(
    file_id: int,
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the file content by its ID.

    Parameters
    ----------
    file_id : int
        The ID of the file to get.
    db : Session
        The current database session.

    Returns
    -------
    FileResponse
        The file content.
    """
    db_file = get_file(db, file_id)
    has_permission(current_user, "file", "read", db_file)
    if db_file.file_type in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
        return FileResponse(
            db_file.file_path
        )
    return FileResponse(
        db_file.file_path,
        filename=db_file.file_name,
    )


# ------- Update ------- #

@router.patch("/{file_id}", response_model=FileReadDB)
def patch_file(
    file_id: int,
    file: FileUpdate,
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update a file by its ID.

    Parameters
    ----------
    file_id : int
        The ID of the file to update.
    file : FileUpdate
        The file object with the updated data.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    FileReadDB
        The updated file object.
    """
    db_file = get_file(db, file_id)
    has_permission(current_user, "file", "update", db_file)
    return update_file(db, db_file, file)

# ------- Delete ------- #


@router.delete("/{file_id}", response_class=Response)
def remove_file(
    file_id: int,
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a file by its ID.

    Parameters
    ----------
    file_id : int
        The ID of the file to delete.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    Response
        A response with a status code of 200 if the file is deleted successfully, 
        or a response with a status code of 400 or 401 if there is an error.
    """
    db_file = get_file(db, file_id)
    has_permission(current_user, "file", "delete", db_file)
    if not delete_file(db, db_file):
        raise HTTPException(status_code=400, detail="Failed to delete file")
    return Response(status_code=200)
