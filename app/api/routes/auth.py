"""
Authentication logic for the API.

This module contains the authentication logic for the API. It includes
the routes for logging in and out, as well as the routes for generating
and verifying the One-Time-Password (OTP) QR code.

@file: ./app/api/routes/auth.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from io import BytesIO
from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi.params import Depends, Header
from fastapi.responses import RedirectResponse, Response
from fastapi.security import OAuth2PasswordRequestForm
import qrcode
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.object.user import get_current_user, get_user, get_user_by_email, update_user
from app.core.security import (
    Token, TokenData,
    authenticate_user, decode_access_token, validate_otp,
    create_access_token, generate_otp
)
from app.templates.schemas.user import UserReadDB, UserUpdate


router = APIRouter()


@router.post("/login", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Login user and return an access token.

    Parameters
    ----------
    form_data : OAuth2PasswordRequestForm
        Form with username and password.

    Returns
    -------
    Token
        access token with user uuid and permission.
    """
    user = await authenticate_user(
        db=db, username=form_data.username, password=form_data.password, request=request)
    return create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=user.uuid,
            permission=user.permission
        ))


@router.post("/OTP", response_model=Token)
def login_otp(
    otp_code: str,
    authorization_header: str = Header(),
    db: Session = Depends(get_db)
):
    """
    Verify the OTP code and return an access token.

    Parameters
    ----------
    otp_code : str
        The OTP code to verify.
    authorization_header : str
        The header with the OTP token from the previous request.
    db : Session
        The database session to use.

    Returns
    -------
    Token
        access token with user uuid and permission.

    Raises
    ------
    HTTPException
        401 Unauthorized if the OTP code is invalid or OTP is not enabled.
    """
    token_data = decode_access_token(authorization_header)
    if token_data.purpose != "OTP":
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = get_user(db, token_data.uuid)
    if user.otp_method == "none":
        raise HTTPException(status_code=401, detail="OTP not enabled")
    if not validate_otp(
        user_username=user.username,
        user_otp_secret=user.otp_secret,
        otp=otp_code,
        method=user.otp_method
    ):
        raise HTTPException(status_code=401, detail="Invalid OTP code")
    return create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=user.uuid,
            permission=user.permission
        ))


@router.get("/QR", response_class=Response)
def get_otp_qr(current_user: UserReadDB = Depends(get_current_user)):
    """
    Generate a QR code with the user's OTP URI and return it as an image.

    Parameters
    ----------
    current_user : UserReadDB
        The user who is requesting the QR code.

    Returns
    -------
    Response
        An HTTP response with the QR code image.
    """
    uri, secret = generate_otp(
        current_user.uuid, current_user.username, current_user.otp_secret)
    qr = qrcode.make(uri)
    img_io = BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    return Response(
        content=img_io.getvalue(),
        headers={'secret': secret},
        media_type="image/png"
    )


@router.get("/email/verify", response_class=RedirectResponse)
def verify_email(token: str, db: Session = Depends(get_db)):
    """
    Verify a user's email address by its verification token.

    Parameters
    ----------
    token : str
        The verification token sent to the user's email.
    db : Session
        The current database session.

    Returns
    -------
    RedirectResponse
        A redirect to the frontend URL.

    Raises
    ------
    HTTPException
        401 Unauthorized if the token is invalid.
    """
    token_data = decode_access_token(token)
    if token_data.purpose != "email-verification":
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = get_user_by_email(db, token_data.email)
    if user.uuid != token_data.uuid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = update_user(db, user.uuid, UserUpdate(email_verified=True))
    return RedirectResponse(url=settings.FRONTEND_URL)
