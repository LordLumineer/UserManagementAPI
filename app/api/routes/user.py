from fastapi import APIRouter, UploadFile, Depends, File, Header, Query
from fastapi.background import P
from fastapi.exceptions import HTTPException
from fastapi.responses import Response, FileResponse
from PIL import Image
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.object.file import create_file, delete_file, get_file
from app.core.object.user import (
    create_user, get_user, update_user, delete_user,
    get_users, get_users_list, get_current_user,
    link_file_to_user,
)
from app.core.security import decode_access_token
from app.core.utils import extract_initials_from_text, generate_profile_picture
from app.templates.schemas.file import FileCreate, FileReadDB
from app.templates.schemas.user import UserCreate, UserRead, UserReadDB, UserUpdate

router = APIRouter()

# ~~~~~ CRUD ~~~~~ #
# ------- Create ------- #


@router.post("/", response_model=UserReadDB)  # , response_model=UserReadDB)
def new_user(
    user: UserCreate,
    token: str | None = Header(None),
    db: Session = Depends(get_db)
):
    if token:
        token_data = decode_access_token(token)
        if "permission" in list(token_data.keys()):
            if token_data["permission"] == "admin":
                return create_user(db, user)
    user.permission = "user"        # NOTE: Override to ensure default permission
    user.email_verified = False     # NOTE: Override to ensure email verification
    return create_user(db, user)


@router.put("/{uuid}/image", response_model=FileReadDB)
async def new_user_image(
    uuid: str,
    file: UploadFile = File(...),
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if file.filename.split('.')[-1].lower() not in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
        raise HTTPException(
            status_code=400, detail="File must be a valid image format")
    img = Image.open(file.file)
    if img.width > 512 or img.height > 512:
        raise HTTPException(
            status_code=400, detail=f"Image must be below 512x512 px ({img.width}x{img.height}px)")
    file.file.seek(0)  # Reset pointer to the beginning of the file
    
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    file.filename = f"pfp_{uuid}.{file.filename.split('.')[-1].lower()}"
    new_file = FileCreate(
        file_name=file.filename,
        created_by=current_user.uuid
    )
    db_user = get_user(db, uuid)
    if db_user.profile_picture_id:
        delete_file(db, db_user.profile_picture_id)
    
    file_db = await create_file(db, new_file, file)
    link_file_to_user(db, uuid, file_db.id)
    update_user(db, uuid, UserUpdate(profile_picture_id=file_db.id))
    return file_db


@router.put("/{uuid}/file", response_model=FileReadDB)
async def new_user_file(
    uuid: str,
    file: UploadFile = File(...),
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    new_file = FileCreate(
        file_name=file.filename,
        created_by=current_user.uuid
    )
    file_db = await create_file(db, new_file, file)
    link_file_to_user(db, uuid, file_db.id)
    return file_db

# ------- Read ------- #


@router.get("/", response_model=list[UserReadDB])
def read_users(
    skip: int = 0, limit: int = 100,
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_users(db, skip=skip, limit=limit)


@router.get("/users", response_model=list[UserReadDB])
def read_users_list(
    users_ids: list[str] = Query(default=[]),
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_users_list(db, users_ids)


@router.get("/me", response_model=UserRead)
def read_users_me(current_user: UserReadDB = Depends(get_current_user)):
    return current_user


@router.get("/{uuid}", response_model=UserRead)
def read_user(uuid: str, db: Session = Depends(get_db)):
    return get_user(db, uuid)


@router.get("/{uuid}/image", response_class=FileResponse)
async def read_user_image(uuid: str, db: Session = Depends(get_db)):
    user = get_user(db, uuid)
    try:
        file = get_file(db, user.profile_picture_id)
    except HTTPException as e:
        if e.status_code == 404:
            file = None
    if not file:
        letters = extract_initials_from_text(user.username)
        return await generate_profile_picture(letters)
    return FileResponse(
        file.file_path,
        # filename=file.file_name,
        # media_type=f"image/{file.file_type.replace('.', '')}"
    )

# ------- Update ------- #


@router.patch("/{uuid}", response_model=UserRead)
def patch_user(
    uuid: str,
    user: UserUpdate,
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    return update_user(db, uuid, user)


@router.patch("/{uuid}/image")
def patch_user_image():
    raise HTTPException(
        status_code=301,
        detail=f"""Invalid endpoint. Use PUT {settings.BASE_URL}{
            settings.API_STR}/files/`file_id` instead"""
    )


@router.patch("/{uuid}/file")
def patch_user_file():
    raise HTTPException(
        status_code=301,
        detail=f"""Invalid endpoint. Use PUT {settings.BASE_URL}{
            settings.API_STR}/files/`file_id` instead"""
    )

# ------- Delete ------- #


@router.delete("/{uuid}", response_class=Response)
def remove_user(
    uuid: str,
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.uuid != uuid and current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not delete_user(db, uuid):
        raise HTTPException(status_code=400, detail="Failed to delete user")
    return Response(status_code=200)


@router.delete("/{uuid}/image")
def remove_user_image():
    raise HTTPException(
        status_code=301,
        detail=f"""Invalid endpoint. Use DELETE {settings.BASE_URL}
        {settings.API_STR}/files/`file_id` instead"""
    )


@router.delete("/{uuid}/file")
def remove_user_file():
    raise HTTPException(
        status_code=301,
        detail=f"""Invalid endpoint. Use DELETE {settings.BASE_URL}
        {settings.API_STR}/files/`file_id` instead"""
    )
