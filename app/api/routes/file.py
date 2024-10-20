"""
This module contains the API endpoints related to the files (e.g. upload, download, delete, update).

@file: ./app/api/routes/file.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from fastapi import APIRouter, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.params import Depends, File, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.object.file import create_file, delete_file, get_file, get_files, get_files_list, update_file
from app.core.object.user import get_current_user
from app.templates.schemas.file import FileCreate, FileRead, FileReadDB, FileUpdate
from app.templates.schemas.user import UserReadDB


router = APIRouter()

# ~~~~~ CRUD ~~~~~ #
# ------- Create ------- #


@router.post("/", response_model=FileReadDB)
async def new_file(
    description: str | None = Query(default=None),
    file: UploadFile = File(...),
    current_user: UserReadDB = Depends(get_current_user),
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
    current_user : UserReadDB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    FileReadDB
        The new file object.
    """
    new_file_create = FileCreate(
        description=description,
        file_name=file.filename,
        created_by=current_user.uuid
    )
    return await create_file(db, new_file_create, file)

# ------- Read ------- #


@router.get("/", response_model=list[FileReadDB])
def read_files(
    skip: int = Query(default=0), limit: int = Query(default=100),
    current_user: UserReadDB = Depends(get_current_user),
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
    current_user : UserReadDB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    list[FileReadDB]
        A list of file objects.
    """
    if current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_files(db, skip=skip, limit=limit)


@router.get("/files", response_model=list[FileReadDB])
def read_files_list(
    files_ids: list[int] = Query(default=[]),
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a list of files based on their IDs

    Parameters
    ----------
    files_ids : list[int], optional
        The IDs of the files to get (default is an empty list).
    current_user : UserReadDB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    list[FileReadDB]
        A list of file objects.
    """
    if current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_files_list(db, files_ids)


@router.get("/{file_id}", response_model=FileRead)
def read_file(file_id: int, db: Session = Depends(get_db)):
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
    return get_file(db, file_id)


@router.get("/{file_id}/file", response_class=FileResponse)
async def read_file_file(file_id: int, db: Session = Depends(get_db)):
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
    file = get_file(db, file_id)
    if file.file_type in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
        return FileResponse(
            file.file_path
        )
    return FileResponse(
        file.file_path,
        filename=file.file_name,
    )


# ------- Update ------- #

@router.patch("/{file_id}", response_model=FileReadDB)
def patch_file(
    file_id: int,
    file: FileUpdate,
    current_user: UserReadDB = Depends(get_current_user),
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
    current_user : UserReadDB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    FileReadDB
        The updated file object.
    """
    db_file = get_file(db, file_id)
    if current_user.uuid != db_file.created_by and current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return update_file(db, file_id, file)

# ------- Delete ------- #


@router.delete("/{file_id}", response_class=Response)
def remove_file(
    file_id: int,
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a file by its ID.

    Parameters
    ----------
    file_id : int
        The ID of the file to delete.
    current_user : UserReadDB
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
    if current_user.uuid != db_file.created_by and current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not delete_file(db, file_id):
        raise HTTPException(status_code=400, detail="Failed to delete file")
    return Response(status_code=200)
