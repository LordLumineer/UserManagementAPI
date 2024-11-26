"""
Admin module.

This module contains the API endpoints and logic for the administration panel. 
It includes functions for managing users, viewing logs, and other admin-related tasks.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Form, Response, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.config import logger
from app.core.db import get_db
from app.core.permissions import FeatureFlags, has_permission, save_feature_flags
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
    if user_id == current_user.uuid:
        raise HTTPException(status_code=400, detail="You cannot ban yourself")
    db_user = get_user(db, user_id)
    has_permission(current_user, "admin", "ban", db_user)

    reason = f"{datetime.now(timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S %Z')}: {reason}"
    if db_user.deactivated_reason:
        reason = db_user.deactivated_reason + f"\n{reason}"

    db_user = await update_user(db, db_user, UserUpdate(is_active=False, deactivated_reason=reason))
    logger.warning(
        f"Admin: {current_user.username}, Action: Banned, User: {
            db_user.username}, Reason: {reason}",
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
    db_user = get_user(db, user_id)
    has_permission(current_user, "admin", "un-ban", db_user)

    reason = f"{datetime.now(timezone.utc).strftime(
        '%Y-%m-%d %H:%M:%S %Z')}: Unbanned"
    if db_user.deactivated_reason:
        reason = db_user.deactivated_reason + f"\n{reason}"

    db_user = await update_user(db, db_user, UserUpdate(is_active=False, deactivated_reason=reason))
    logger.warning(
        f"Admin: {current_user.username}, Action: Un-Banned, User: {
            db_user.username}, Reason: {reason}",
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


@router.patch("/feature_flags", response_model=dict)
def update_feature_flags(
    remove: FeatureFlags | None = Form(default=None),
    add: FeatureFlags | None = Form(default=None),
    current_user: User_DB = Depends(get_current_user),
):
    """
    Update the feature flags in memory and save them to a file.

    Parameters
    ----------
    remove : FeatureFlags | None
        A dictionary of feature names to remove from the feature flags.
    add : FeatureFlags | None
        A dictionary of feature names and rules to add to the feature flags.
    current_user : User_DB
        The user object of the user who is making the request.

    Returns
    -------
    dict
        The updated feature flags.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not an admin.
    """
    has_permission(current_user, "admin", "feature_flags")
    from app.core.permissions import FEATURE_FLAGS  # pylint: disable=C0415
    if add is None:
        add = []
    if remove is None:
        remove = []
    for feature_name, feature_rule in remove.items():
        if feature_name in FEATURE_FLAGS:
            del FEATURE_FLAGS[feature_name]
    for feature_name, feature_rule in add.items():
        FEATURE_FLAGS[feature_name] = jsonable_encoder(feature_rule)
    if add or remove:
        save_feature_flags()
    return FEATURE_FLAGS
