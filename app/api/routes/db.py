from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, Response, UploadFile, Depends, File
from fastapi.exceptions import HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db, handle_database_import, export_db
from app.core.object.user import get_current_user
from app.core.utils import remove_file
from app.templates.schemas.user import UserReadDB


router = APIRouter()


@router.get("/export")
async def db_export(
    background_tasks: BackgroundTasks,
    current_user: UserReadDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.permission != "admin":
        raise HTTPException(
            status_code=401, detail="Unauthorized")
    file_path = await export_db(db)
    background_tasks.add_task(remove_file, file_path)
    return FileResponse(
        path=file_path,
        filename=f'{settings.PROJECT_NAME}_export_{
            int(datetime.now(timezone.utc).timestamp())}.db',
        media_type="application/octet-stream"
    )


@router.post("/recover")
async def db_recover(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: UserReadDB = Depends(get_current_user)
):
    if current_user.permission != "admin":
        raise HTTPException(
            status_code=401, detail="Unauthorized")
    # Save the uploaded file temporarily
    uploaded_db_path = f"../data/temp_{file.filename}"
    with open(uploaded_db_path, "wb") as buffer:
        buffer.write(await file.read())

    # Call function to handle database import logic
    success = await handle_database_import(uploaded_db_path, "recover")
    if not success:
        raise HTTPException(
            status_code=500, detail="Failed to recover database")
    background_tasks.add_task(remove_file, uploaded_db_path)

    return Response(
        status_code=200,
        content=f"Database recovered from {file.filename}"
    )

@router.post("/import")
async def db_import(
    file: UploadFile = File(...),
    current_user: UserReadDB = Depends(get_current_user)
):
    if current_user.permission != "admin":
        raise HTTPException(
            status_code=401, detail="Unauthorized")

    # Save the uploaded file temporarily
    uploaded_db_path = f"./temp_{file.filename}"
    with open(uploaded_db_path, "wb") as buffer:
        buffer.write(await file.read())

    # Call function to handle database import logic
    await handle_database_import(uploaded_db_path, "import")

    return Response(
        status_code=200,
        content=f"Database imported from {file.filename}"
    )
