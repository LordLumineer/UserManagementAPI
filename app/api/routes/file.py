
from fastapi import APIRouter, Depends, File, Query, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.responses import Response, FileResponse
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
    new_file_create = FileCreate(
        description=description,
        file_name=file.filename,
        created_by=current_user.uuid
    )
    return await create_file(db, new_file_create, file)

# ------- Read ------- #


@router.get("/", response_model=list[FileReadDB])
def read_files(
    skip: int = 0, limit: int = 100,
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_files(db, skip=skip, limit=limit)


@router.get("/files", response_model=list[FileReadDB])
def read_files_list(
    files_ids: list[int] = Query(default=[]),
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return get_files_list(db, files_ids)


@router.get("/{file_id}", response_model=FileRead)
def read_file(file_id: int, db: Session = Depends(get_db)):
    return get_file(db, file_id)


@router.get("/{id}/file", response_class=FileResponse)
async def read_file_file(file_id: int, db: Session = Depends(get_db)):
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
    db_file = get_file(db, file_id)
    if current_user.uuid != db_file.created_by and current_user.permission not in ["manager", "admin"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not delete_file(db, file_id):
        raise HTTPException(status_code=400, detail="Failed to delete file")
    return Response(status_code=200)
