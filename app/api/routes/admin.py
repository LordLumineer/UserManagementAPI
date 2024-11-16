"""
Admin module.

This module contains the API endpoints and logic for the administration panel. 
It includes functions for managing users, viewing logs, and other admin-related tasks.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Form, Response, Depends
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.config import logger
from app.core.db import get_db
from app.db_objects.user import get_current_user, get_user, update_user
from app.db_objects.db_models import User as User_DB
from app.templates.schemas.user import UserUpdate


router = APIRouter()


@router.post("/ban/{user_id}", response_class=Response)
async def ban_user(
    user_id: str,
    reason: str = Form(...),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Ban a user by its UUID.

    Parameters
    ----------
    user_id : str
        The UUID of the user to ban.
    reason : str, optional
        The reason for the ban (default is "Banned").
    current_user : User_DB
        The user object of the user who is making the request.
    db : Session
        The current database session.

    Returns
    -------
    Response
        A response with a status code of 200 if the user is banned successfully, 
        or a response with a status code of 400 or 401 if there is an error.
    """
    if current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    db_user = get_user(db, user_id)

    reason = f"{datetime.now(timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S %Z')}: {reason}"
    if db_user.deactivated_reason:
        reason = db_user.deactivated_reason + f"\n{reason}"

    db_user = await update_user(db, db_user, UserUpdate(is_active=False, deactivated_reason=reason))
    logger.warning(
        "Admin: %s, Action: Banned, User: %s, Reason: %s",
        current_user.username,
        db_user.username,
        reason
    )
    return JSONResponse(
        status_code=200,
        content={
            "Admin": current_user.username, 
            "Action": "Banned",
            "User": db_user.username,
            "Reason": reason
        }
    )


@router.post("/unban/{user_id}", response_class=Response)
async def unban_user(
    user_id: str,
    reason: str = Form(...),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Unban a user

    Parameters
    ----------
    user_id : str
        The UUID of the user to unban
    current_user : User_DB
        The user object of the user who is making the request
    db : Session
        The current database session

    Returns
    -------
    Response
        A response with a status code of 200 if the user is unbanned successfully, 
        or a response with a status code of 400 or 401 if there is an error
    """
    if current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    db_user = get_user(db, user_id)

    reason = f"{datetime.now(timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S %Z')}: Unbanned"
    if db_user.deactivated_reason:
        reason = db_user.deactivated_reason + f"\n{reason}"

    db_user = await update_user(db, db_user, UserUpdate(is_active=False, deactivated_reason=reason))
    logger.warning(
        "Admin: %s, Action: Banned, User: %s, Reason: %s",
        current_user.username,
        db_user.username,
        reason
    )
    return JSONResponse(
        status_code=200,
        content={
            "Admin": current_user.username, 
            "Action": "Unbanned",
            "User": db_user.username,
            "Reason": reason
        }
    )
