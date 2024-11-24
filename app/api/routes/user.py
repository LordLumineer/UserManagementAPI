"""This module contains the API endpoints related to the users (e.g. create, read, update, delete)."""
import os
from fastapi import APIRouter, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.params import Depends, File, Header, Query
from fastapi.responses import FileResponse, Response
from PIL import Image
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.db_objects.file import create_file, delete_file, get_file, link_file_user
from app.db_objects.user import (
    create_user, get_user, update_user, delete_user,
    get_users, get_users_list, get_current_user,
)
from app.core.security import decode_access_token
from app.core.utils import extract_initials_from_text, generate_profile_picture
from app.db_objects.db_models import User as User_DB
from app.templates.schemas.file import FileCreate, FileReadDB
from app.templates.schemas.user import UserCreate, UserRead, UserReadDB, UserUpdate

router = APIRouter()

# ~~~~~ CRUD ~~~~~ #
# ------- Create ------- #


@router.post("/", response_model=UserRead)
async def new_user(
    user: UserCreate,
    token: str | None = Header(None),
    db: Session = Depends(get_db)
):
    """
    Create a new user.

    If a token is provided, the user will be created with the "admin" permission
    if the token is valid and the user has the "admin" permission.

    Parameters
    ----------
    user : UserCreate
        The user to create.
    token : str, optional
        The token to use to authorize the creation of the user.
    db : Session
        The current database session.

    Returns
    -------
    UserRead
        The new user object.
    """
    if token:
        token_data = decode_access_token(token)
        if token_data.purpose != "login":
            raise HTTPException(status_code=401, detail="Unauthorized")
        db_user = get_user(db, token_data.uuid)
        if db_user.permission == "admin" and token_data.permission == "admin":
            return create_user(db, user)
    user.permission = "user"        # NOTE: Override to ensure default permission
    user.email_verified = False     # NOTE: Override to ensure email verification
    return await create_user(db, user)


@router.put("/{uuid}/image", response_model=FileReadDB)
async def new_user_image(
    uuid: str,
    description: str | None = Query(default=None),
    file: UploadFile = File(...),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upload a new profile picture for the user with the given UUID.
    - The file must be a valid image format (png, jpg, jpeg, gif, or bmp) and must be below 512x512 px.
    - If the user is not the same as the current user and the current user does not have permission "admin", 
        then a 401 error is raised.
    - The file is saved with the name "pfp_{uuid}.{file_extension}" and is linked to the user.

    Parameters
    ----------
    uuid : str
        The UUID of the user to update.
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

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not the same as the current user 
        and the current user does not have permission "admin".
    """
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    if file.filename.split('.')[-1].lower() not in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
        raise HTTPException(
            status_code=400, detail="File must be a valid image format")
    img = Image.open(file.file)
    if img.width > 512 or img.height > 512:
        raise HTTPException(
            status_code=400, detail=f"Image must be below 512x512 px ({img.width}x{img.height}px)")
    file.file.seek(0)  # Reset pointer to the beginning of the file

    db_user = get_user(db, uuid)
    file.filename = f"pfp_{uuid}.{file.filename.split('.')[-1].lower()}"
    new_file = FileCreate(
        description=description,
        file_name=os.path.join("users", db_user.uuid, file.filename),
        created_by_uuid=current_user.uuid
    )
    if db_user.profile_picture_id:
        db_file = get_file(db, db_user.profile_picture_id, raise_error=False)
        if db_file:
            delete_file(db, db_file)

    file_db = await create_file(db, new_file, file)
    link_file_user(db, db_user, file_db)
    await update_user(db, db_user, UserUpdate(profile_picture_id=file_db.id))
    return file_db


@router.put("/{uuid}/file", response_model=FileReadDB)
async def new_user_file(
    uuid: str,
    description: str | None = Query(default=None),
    file: UploadFile = File(...),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upload a new file for a user.

    Parameters
    ----------
    uuid : str
        The UUID of the user to upload the file to.
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
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")

    new_file = FileCreate(
        description=description,
        file_name=os.path.join("files", file.filename),
        created_by_uuid=current_user.uuid
    )
    db_user = get_user(db, uuid)
    file_db = await create_file(db, new_file, file)
    link_file_user(db, db_user, file_db)
    return file_db


@router.put("{uuid}/blocked_users", response_model=list[str])
def block_users(
    uuid: str,
    users_ids: list[str] = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Block a list of users by their UUIDs.

    Parameters
    ----------
    uuid : str
        The UUID of the user to block.
    users_ids : list[str]
        A list of UUIDs of the users to block.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    UserRead
        The updated user object.
    """
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    db_user = get_user(db, uuid)
    for blocked_uuid in users_ids:
        if blocked_uuid in db_user.blocked_uuids:
            continue
        db_user.blocked_uuids.append(blocked_uuid)
    db.commit()
    db.refresh(db_user)
    return db_user.blocked_uuids


# ------- Read ------- #


@router.get("/", response_model=list[UserRead])
def read_users(
    skip: int = Query(default=0), limit: int = Query(default=100),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a list of users

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
    list[UserReadDB]
        A list of user objects.
    """
    if current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_users(db, skip=skip, limit=limit)


@router.get("/users", response_model=list[UserReadDB])
def read_users_list(
    users_ids: list[str] = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a list of users by their UUIDs

    Parameters
    ----------
    users_ids : list[str]
        A list of user UUIDs (default is an empty list)
    current_user : User_DB
        The user object of the user who is making the request
    db : Session
        The current database session

    Returns
    -------
    list[UserReadDB]
        A list of user objects
    """
    if current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_users_list(db, users_ids)


@router.get("/me", response_model=UserRead)
def read_users_me(current_user: UserReadDB = Depends(get_current_user)):
    """
    Get the current user.

    Parameters
    ----------
    current_user : User_DB
        The user object of the user who is making the request.

    Returns
    -------
    UserRead
        The current user object.
    """
    return current_user


@router.get("/{uuid}/data", response_model=UserRead)
def read_user(uuid: str, db: Session = Depends(get_db)):
    """
    Get a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to get.
    db : Session
        The current database session.

    Returns
    -------
    UserRead
        The user object.
    """
    db_user = get_user(db, uuid)
    return db_user


@router.get("/{uuid}/image", response_class=FileResponse)
async def read_user_image(uuid: str, db: Session = Depends(get_db)):
    """
    Get the profile picture of a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to get the profile picture of.
    db : Session
        The current database session.

    Returns
    -------
    FileResponse
        The profile picture of the user.

    Notes
    -----
    If the user does not have a profile picture, a default profile picture is generated.
    """
    db_user = get_user(db, uuid)
    db_file = get_file(db, db_user.profile_picture_id, raise_error=False)
    if not db_file:
        letters = extract_initials_from_text(db_user.display_name)
        return await generate_profile_picture(letters)
    return FileResponse(
        db_file.file_path,
        # filename=file.file_name,
        # media_type=f"image/{file.file_type}"
    )


# ------- Update ------- #


@router.patch("/{uuid}", response_model=UserRead)
async def patch_user(
    uuid: str,
    user: UserUpdate,
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to update.
    user : UserUpdate
        The user object with the updated data.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    UserRead
        The updated user object.
    """
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    if current_user.uuid == uuid:
        user.permission = None  # NOTE: A User can't change their own permission
    return await update_user(db, get_user(db, uuid), user)


@router.patch("/{uuid}/image")
def patch_user_image():
    """
    Update the profile picture of a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to update.
    file : File
        The new profile picture.

    Raises
    ------
    HTTPException
        A 301 status code is raised with a detail message indicating that the endpoint should be used instead.

    Notes
    -----
    This endpoint is invalid and should not be used.
    """
    raise HTTPException(
        status_code=301,
        detail=f"""Invalid endpoint. Use PUT {settings.BASE_URL}{
            settings.API_STR}/files/`file_id` instead"""
    )


@router.patch("/{uuid}/file")
def patch_user_file():
    """
    Update the profile picture of a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to update.
    file : File
        The new profile picture.

    Raises
    ------
    HTTPException
        A 301 status code is raised with a detail message indicating that the endpoint should be used instead.

    Notes
    -----
    This endpoint is invalid and should not be used.
    """
    raise HTTPException(
        status_code=301,
        detail=f"""Invalid endpoint. Use PUT {settings.BASE_URL}{
            settings.API_STR}/files/`file_id` instead"""
    )


@router.patch("{uuid}/blocked_users", response_model=list[str])
def update_blocked_users(
    uuid: str,
    remove: list[str] | None = Query(default=[]),
    add: list[str] | None = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Update the list of blocked users for a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to update.
    add : list[str], optional
        A list of UUIDs of users to add to the blocked users list (default is an empty list).
    remove : list[str], optional
        A list of UUIDs of users to remove from the blocked users list (default is an empty list).

    Returns
    -------
    list[str]
        The updated list of blocked users UUIDs.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not the same as the current user 
            and the current user does not have permission "admin".
    """

    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    db_user = get_user(db, uuid)
    for blocked_uuid in remove:
        if blocked_uuid not in db_user.blocked_uuids:
            continue
        db_user.blocked_uuids.remove(blocked_uuid)
    for blocked_uuid in add:
        if blocked_uuid in db_user.blocked_uuids:
            continue
        db_user.blocked_uuids.append(blocked_uuid)
    db.commit()
    db.refresh(db_user)
    return db_user.blocked_uuids


# ------- Delete ------- #


@router.delete("/{uuid}", response_class=Response)
async def remove_user(
    uuid: str,
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to delete.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    Response
        A response with a status code of 200 if the user is deleted successfully, 
        or a response with a status code of 400 or 401 if there is an error.
    """
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not await delete_user(db, get_user(db, uuid)):
        raise HTTPException(status_code=400, detail="Failed to delete user")
    return Response(status_code=200)


@router.delete("/{uuid}/image")
def remove_user_image():
    """
    Delete the profile picture of a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to delete the profile picture of.

    Raises
    ------
    HTTPException
        A 301 status code is raised with a detail message indicating that the endpoint should be used instead.

    Notes
    -----
    This endpoint is invalid and should not be used.
    """
    raise HTTPException(
        status_code=301,
        detail=f"""Invalid endpoint. Use DELETE {settings.BASE_URL}{
            settings.API_STR}/files/`file_id` instead"""
    )


@router.delete("/{uuid}/file")
def remove_user_file():
    """
    Delete the file of a user by its UUID.

    Parameters
    ----------
    uuid : str
        The UUID of the user to delete the file of.

    Raises
    ------
    HTTPException
        A 301 status code is raised with a detail message indicating that the endpoint should be used instead.

    Notes
    -----
    This endpoint is invalid and should not be used.
    """
    raise HTTPException(
        status_code=301,
        detail=f"""Invalid endpoint. Use DELETE {settings.BASE_URL}{
            settings.API_STR}/files/`file_id` instead"""
    )


@router.delete("{uuid}/blocked_users", response_model=list[str])
def delete_blocked_users(
    uuid: str,
    users_ids: list[str] | None = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Delete a list of blocked users by their UUIDs.

    Parameters
    ----------
    uuid : str
        The UUID of the user to delete the blocked users of.
    users_ids : list[str]
        A list of UUIDs of the users to delete from the blocked users list.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    list[str]
        The updated list of blocked users UUIDs.
    """
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    db_user = get_user(db, uuid)
    for blocked_uuid in users_ids:
        if blocked_uuid not in db_user.blocked_uuids:
            continue
        db_user.blocked_uuids.remove(blocked_uuid)
    db.commit()
    db.refresh(db_user)
    return db_user.blocked_uuids
