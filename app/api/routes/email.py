"""
Email-related API endpoints.

This module contains the API endpoints related to the email 
(e.g. send email, send OTP, send reset password email, send test email, send validation email).

@file: ./app/api/routes/email.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi.params import Body, Depends, Query
import pyotp
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.email import (
    send_email, send_otp_email, send_reset_password_email, send_test_email, send_validation_email
)
from app.core.permissions import has_permission
from app.db_objects.user import get_current_user, get_nb_users, get_user_by_email, get_users
from app.core.security import TokenData, create_access_token
from app.db_objects.db_models import User as User_DB


router = APIRouter()


@router.post("/send-email")
async def send_email_single(
    confirm: bool = Query(default=False),
    subject: str = Query(),
    recipient: str = Query(),
    content: str = Body(),
    current_user: User_DB = Depends(get_current_user)
):
    """
    Send an email to a single recipient.

    Parameters
    ----------
    confirm : bool, default=False
        Whether to proceed with sending the email.
    subject : str
        The subject of the email.
    recipient : str
        The recipient of the email.
    content : str
        The content of the email.
    current_user : User_DB
        The user who is sending the email.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to send the email.
    """
    has_permission(current_user, "email", "single")
    if not confirm:
        raise HTTPException(status_code=400, detail="You must confirm the email")
    return await send_email([recipient], subject, content)


@router.post("/send-email-multiple")
async def send_email_multiple(
    confirm: bool = Query(default=False),
    subject: str = Query(),
    recipients: list[str] = Query(),
    content: str = Body(),
    current_user: User_DB = Depends(get_current_user)
):
    """
    Send an email to multiple recipients.

    Parameters
    ----------
    confirm : bool, default=False
        Whether to proceed with sending the email.
    subject : str
        The subject of the email.
    recipients : list[str]
        A list of recipients of the email.
    content : str
        The content of the email.
    current_user : User_DB
        The user who is sending the email.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to send the email.
    """
    has_permission(current_user, "email", "multiple")
    if not confirm:
        raise HTTPException(status_code=400, detail="You must confirm the email")
    return await send_email(recipients, subject, content)


@router.post("/send-email-all")
async def send_email_all(
    confirm: bool = Query(default=False),
    subject: str = Query(),
    content: str = Body(),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Send an email to all users in the database.

    Parameters
    ----------
    confirm : bool
        Whether to proceed with sending the email.
    subject : str
        The subject of the email.
    content : str
        The content of the email.
    current_user : User_DB
        The user who is sending the email.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to send the email.
    """
    has_permission(current_user, "email", "all")
    if not confirm:
        raise HTTPException(status_code=400, detail="You must confirm the email")
    users = get_users(db, skip=0, limit=get_nb_users(db))
    recipients = [user.email for user in users]
    return await send_email(recipients, subject, content)


@router.post("/send-test-email")
async def test_email(
    recipient: str = Query(default=settings.CONTACT_EMAIL),
    current_user: User_DB = Depends(get_current_user)
):
    """
    Send a test email to a single recipient.

    Parameters
    ----------
    recipient : str, optional
        The recipient of the email. Defaults to the contact email in settings.
    current_user : User_DB
        The user who is sending the email.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to send the email.
    """
    has_permission(current_user, "email", "test")
    return await send_test_email(recipient)


@router.post("/send-otp-email")
async def otp_email(
    request: Request,
    confirm: bool = Query(default=False),
    recipient: str = Query(default=settings.CONTACT_EMAIL),
    current_user: User_DB = Depends(get_current_user)
):
    """
    Send an email with a one-time password to a single recipient.

    Parameters
    ----------
    request : Request
        The request object.
    recipient : str, optional
        The recipient of the email. Defaults to the contact email in settings.
    current_user : User_DB
        The user who is sending the email.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to send the email.
    """
    has_permission(current_user, "email", "auth")
    if not confirm:
        raise HTTPException(status_code=400, detail="You must confirm the email")
    totp = pyotp.TOTP(
        s=current_user.otp_secret,
        name=current_user.username,
        interval=settings.OTP_EMAIL_INTERVAL,
        issuer=settings.PROJECT_NAME,
        digits=settings.OTP_LENGTH
    )
    return await send_otp_email(
        recipient=recipient,
        otp_code=totp.now(),
        request=request
    )


@router.post("/send-reset-password-email")
async def reset_password_email(
    request: Request,
    confirm: bool = Query(default=False),
    recipient: str = Query(default=settings.CONTACT_EMAIL),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Send a reset password email to a single recipient.

    Parameters
    ----------
    recipient : str, optional
        The recipient of the email. Defaults to the contact email in settings.
    current_user : User_DB
        The user who is sending the email.
    db : Session
        The database session.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to send the email.
    """
    has_permission(current_user, "email", "auth")
    if not confirm:
        raise HTTPException(status_code=400, detail="You must confirm the email")
    user = get_user_by_email(db, recipient)
    token = create_access_token(
        sub=TokenData(
            purpose="reset-password",
            uuid=user.uuid,
            username=user.username
        ))
    return await send_reset_password_email(recipient, token, request)


@router.post("/send-validation-email")
async def validation_email(
    confirm: bool = Query(default=False),
    recipient: str = Query(default=settings.CONTACT_EMAIL),
    current_user: User_DB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Send an email to a single recipient to verify their email address.

    Parameters
    ----------
    recipient : str, optional
        The recipient of the email. Defaults to the contact email in settings.
    current_user : User_DB
        The user who is sending the email.
    db : Session
        The database session.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to send the email.
    """
    has_permission(current_user, "email", "auth")
    if not confirm:
        raise HTTPException(status_code=400, detail="You must confirm the email")
    user = get_user_by_email(db, recipient)
    token = create_access_token(
        sub=TokenData(
            purpose="email-verification",
            uuid=user.uuid,
            email=user.email
        ))
    return await send_validation_email(recipient, token)
