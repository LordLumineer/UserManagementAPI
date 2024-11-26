"""
Database-related API endpoints.

This module contains the API endpoints related to the database (e.g. export, import, recover).
"""
from datetime import datetime, timezone
import os
from fastapi import APIRouter, BackgroundTasks, Response, UploadFile, Depends, File
from fastapi.exceptions import HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db, handle_database_import, export_db
from app.core.permissions import has_permission
from app.core.utils import app_path, remove_file
from app.db_objects.user import get_current_user
from app.db_objects.db_models import User as User_DB


router = APIRouter()


@router.get("/export")
async def db_export(
    background_tasks: BackgroundTasks,
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Export the current database to a file.

    Parameters
    ----------
    background_tasks : BackgroundTasks
        A list of tasks to run in the background.
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    FileResponse
        A response with a file attachment containing the database export.
    """
    has_permission(current_user, "db", "export")
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
    current_user: User_DB = Depends(get_current_user)
):
    """
    Recover the database from an uploaded SQLite file.

    This function takes a SQLite file as input and recovers the database 
    by replacing all existing data in the current database with the data from the uploaded database.

    If a row does not exist in the current database, it will be added. 
    If a row exists, its data will be replaced with the data from the uploaded database if the data is different.

    The uploaded database file is removed after the recovery is complete.

    Parameters
    ----------
    background_tasks : BackgroundTasks
        A list of tasks to run in the background.
    file : UploadFile
        The uploaded SQLite file.
    current_user : User_DB
        The user object of the user who is making the request.

    Returns
    -------
    Response
        A response with a status code of 200 and a message indicating that the database recovery was successful.
    """
    has_permission(current_user, "db", "recover")
    # Save the uploaded file temporarily
    uploaded_db_path = app_path(os.path.join("data", f"temp_{file.filename}"))
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
    current_user: User_DB = Depends(get_current_user)
):
    """
    Import the database from an uploaded SQLite file.

    This function takes a SQLite file as input and imports the database 
    by adding any new rows from the uploaded database to the current database 
    and updating any existing rows with different data.

    Existing data in the current database will not be overwritten.

    The uploaded database file is removed after the import is complete.

    Parameters
    ----------
    file : UploadFile
        The uploaded SQLite file.
    current_user : User_DB
        The user object of the user who is making the request.

    Returns
    -------
    Response
        A response with a status code of 200 and a message indicating that the database import was successful.

    Notes
    -----
    This function takes a SQLite file as input and imports the database 
    by adding any new rows from the uploaded database to the current database 
    and updating any existing rows with different data.

    The uploaded database file is removed after the import is complete.
    """
    has_permission(current_user, "db", "import")

    # Save the uploaded file temporarily
    uploaded_db_path = app_path(f"temp_{file.filename}")
    with open(uploaded_db_path, "wb") as buffer:
        buffer.write(await file.read())

    # Call function to handle database import logic
    await handle_database_import(uploaded_db_path, "import")

    return Response(
        status_code=200,
        content=f"Database imported from {file.filename}"
    )
