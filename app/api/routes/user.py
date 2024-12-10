"""This module contains the API endpoints related to the users (e.g. create, read, update, delete)."""
from fastapi import APIRouter, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.params import Depends, File, Query
from fastapi.responses import FileResponse, Response
from PIL import Image
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import get_async_db
from app.db_objects.file import create_file, delete_file, get_file, link_file_user
from app.db_objects.user import (
    create_user, get_nb_users, get_user, update_user, delete_user,
    get_users, get_users_list, get_current_user,
)
from app.core.permissions import has_permission
from app.core.utils import extract_initials_from_text, generate_profile_picture
from app.db_objects.db_models import User as User_DB
from app.templates.schemas.file import FileCreate, FileReadDB
from app.templates.schemas.user import UserCreate, UserRead, UserUpdate, UserHistory

router = APIRouter()

# ~~~~~ CRUD ~~~~~ #
# ------- Create ------- #


@router.post("/", response_model=UserRead)
async def new_user(
    user: UserCreate,
    db: AsyncSession = Depends(get_async_db),
    current_user: User_DB = Depends(get_current_user),
):
    """
    Create a new user.
    Only Admins and Moderators can create users.
    Only Admins can create Admins and Moderators.

    Parameters
    ----------
    user : UserCreate
        The user object to create.
    db : Session
        The current database session.
    current_user : User_DB
        The user object of the user who is making the request.

    Returns
    -------
    UserRead
        The newly created user object.
    """
    has_permission(current_user, "user", "create", user)
    return await create_user(db, user)


@router.put("/{uuid}/image", response_model=FileReadDB)
async def new_user_image(
    uuid: str,
    description: str | None = Query(default=None),
    file: UploadFile = File(...),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Upload a new profile picture for the user with the given UUID.
    - The file must be a valid image format (png, jpg, jpeg, gif, or bmp)
        and must be below 512x512 px.
    - Only Admins or the user itself can upload a profile picture.
    - The file is saved with the name "pfp_{uuid}.{file_extension}"
        and is linked to the user.

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
        - 400 Bad Request: If the file is not a valid image format.
        - 400 Bad Request: If the file is too large.
    """
    if file.filename.split('.')[-1].lower() not in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
        raise HTTPException(
            status_code=400, detail="File must be a valid image format")
    img = Image.open(file.file)
    if img.width > 512 or img.height > 512:
        raise HTTPException(
            status_code=400, detail=f"Image must be below 512x512 px ({img.width}x{img.height}px)")
    file.file.seek(0)  # Reset pointer to the beginning of the file

    db_user = await get_user(db, uuid)
    has_permission(current_user, "user_image", "create", db_user)

    file.filename = f"pfp_{uuid}.{file.filename.split('.')[-1].lower()}"
    new_file = FileCreate(
        description=description,
        file_name=file.filename,
        created_by_uuid=current_user.uuid
    )
    if db_user.profile_picture_id:
        db_file = await get_file(db, db_user.profile_picture_id, raise_error=False)
        if db_file:
            await delete_file(db, db_file)

    file_db = await create_file(db, new_file, file)
    await link_file_user(db, db_user, file_db)
    await update_user(db, db_user, UserUpdate(
        profile_picture_id=file_db.id,
        action=UserHistory(
            action="profile-picture-updated",
            description=f"Profile picture updated to {file_db.file_name}",
            by=db_user.uuid
        )
    ))
    return file_db


@router.put("/{uuid}/file", response_model=FileReadDB)
async def new_user_file(
    uuid: str,
    description: str | None = Query(default=None),
    file: UploadFile = File(...),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
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
    db_user = await get_user(db, uuid)
    has_permission(current_user, "user_file", "create", db_user)
    new_file = FileCreate(
        description=description,
        file_name=file.filename,
        created_by_uuid=current_user.uuid
    )
    file_db = await create_file(db, new_file, file)
    await link_file_user(db, db_user, file_db)
    return file_db


@router.put("{uuid}/blocked_users", response_model=list[str])
async def block_users(
    uuid: str,
    users_ids: list[str] = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
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
    db_user = await get_user(db, uuid)
    has_permission(current_user, "blocked_users", "create", db_user)
    for blocked_uuid in users_ids:
        if blocked_uuid in db_user.blocked_uuids:
            continue
        db_user.blocked_uuids.append(blocked_uuid)
    await db.commit()
    await db.refresh(db_user)
    return db_user.blocked_uuids


# ------- Read ------- #


@router.get("/", response_model=list[UserRead])
async def read_users(
    skip: int = Query(default=0), limit: int = Query(default=100),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
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
    list[UserRead]
        A list of user objects.
    """
    has_permission(current_user, "user", "read")
    return await get_users(db, skip=skip, limit=limit)


@router.get("/users", response_model=list[UserRead])
async def read_users_list(
    users_ids: list[str] = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
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
    list[UserRead]
        A list of user objects
    """
    has_permission(current_user, "user", "read")
    users = await get_users_list(db, users_ids)
    return users

@router.get("/count", response_model=int)
async def read_users_number(
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Get the number of users.

    Parameters
    ----------
    db : Session
        The current database session.

    Returns
    -------
    int
        The number of user.
    """
    has_permission(current_user, "user", "read")
    return await get_nb_users(db)


@router.get("/me", response_model=UserRead)
def read_users_me(current_user: User_DB = Depends(get_current_user)):
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
    has_permission(current_user, "user", "read", current_user)
    return current_user


@router.get(
    "/{uuid}/details",
    response_model=UserRead,
    response_model_exclude={
        "email",
        "otp_method",
        "blocked_uuids",
        "user_history",
        "external_accounts",
        "email_verified",
        "is_external_only"
    }
)
async def read_user(
    uuid: str,
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Get a user by their UUID.
    Some sensitive fields are excluded from the response,
        you would need to be the user itself to read them.

    Parameters
    ----------
    uuid : str
        The UUID of the user to get.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    UserRead
        The user object.
    """
    db_user = await get_user(db, uuid)
    has_permission(current_user, "user", "read", db_user)
    return db_user


@router.get("/{uuid}/image", response_class=FileResponse)
async def read_user_image(uuid: str, db: AsyncSession = Depends(get_async_db)):
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
    db_user = await get_user(db, uuid)
    db_file = await get_file(db, db_user.profile_picture_id, raise_error=False)
    if not db_file:
        letters = extract_initials_from_text(db_user.display_name)
        return generate_profile_picture(letters)
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
    db: AsyncSession = Depends(get_async_db)
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

    Notes
    -----
    Only moderators and admins can update other users, and only admins can update themselves.
    A User can't change their own roles.
    """
    if (
        not list(set(["moderator", "admin"]) & set(current_user.roles)) or
        (current_user.uuid == uuid and "admin" not in current_user.roles)
    ):
        # NOTE: Only moderators and admins can update other users,
        # and only admins can update themselves.
        user.roles = None
    if (not list(set(["moderator", "admin"]) & set(current_user.roles)) or
            current_user.uuid == uuid):
        # NOTE: A User can't reactivate / deactivate their own account.
        user.is_active = None
    db_user = await get_user(db, uuid)
    has_permission(current_user, "user", "update", {
                   "db_user": db_user, "updates": user})
    return await update_user(db, db_user, user)


@router.patch("{uuid}/blocked_users", response_model=list[str])
async def update_blocked_users(
    uuid: str,
    remove: list[str] | None = Query(default=[]),
    add: list[str] | None = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
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
            and the current user does not have role "admin".
    """
    db_user = await get_user(db, uuid)
    has_permission(current_user, "blocked_users", "update", db_user)
    for blocked_uuid in remove:
        if blocked_uuid not in db_user.blocked_uuids:
            continue
        db_user.blocked_uuids.remove(blocked_uuid)
    for blocked_uuid in add:
        if blocked_uuid in db_user.blocked_uuids:
            continue
        db_user.blocked_uuids.append(blocked_uuid)
    await db.commit()
    await db.refresh(db_user)
    return db_user.blocked_uuids


# ------- Delete ------- #


@router.delete("/{uuid}", response_class=Response)
async def remove_user(
    uuid: str,
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
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
    db_user = await get_user(db, uuid)
    has_permission(current_user, "user", "delete", db_user)

    db_user = await update_user(db, db_user, UserUpdate(
        is_active=False,
        action=UserHistory(
            action="Deleted",
            description="The deletion of this user was requested.",
            by=current_user.uuid
        )))
    if not await delete_user(db, db_user):
        raise HTTPException(status_code=400, detail="Failed to delete user")
    return Response(status_code=200)


@router.delete("{uuid}/blocked_users", response_model=list[str])
async def delete_blocked_users(
    uuid: str,
    users_ids: list[str] | None = Query(default=[]),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
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
    db_user = await get_user(db, uuid)
    has_permission(current_user, "blocked_users", "update", db_user)
    for blocked_uuid in users_ids:
        if blocked_uuid not in db_user.blocked_uuids:
            continue
        db_user.blocked_uuids.remove(blocked_uuid)
    await db.commit()
    await db.refresh(db_user)
    return db_user.blocked_uuids
