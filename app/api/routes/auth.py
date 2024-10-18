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
from tkinter import E
from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi.params import Depends, Form, Header, Query
from fastapi.responses import RedirectResponse, Response
from fastapi.security import OAuth2PasswordRequestForm
import qrcode
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.object.user import create_user, get_current_user, get_user, get_user_by_email, update_user
from app.core.security import (
    Token, TokenData,
    authenticate_user, decode_access_token, validate_otp,
    create_access_token, generate_otp, verify_password
)
from app.core.utils import validate_password
from app.templates.schemas.user import UserCreate, UserReadDB, UserUpdate


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


@router.post("/logout", response_class=Response)
def logout(current_user: UserReadDB = Depends(get_current_user)):
    """
    Logout user and return a response.

    Parameters
    ----------
    current_user : UserReadDB
        The current user object.

    Returns
    -------
    Response
        A response with a status code of 200 if the user is logged out successfully, 
        or a response with a status code of 401 if there is an error.
    """
    return Response(content=f"{current_user.username} | Logged out", status_code=200)


@router.post("/signup", response_model=Token)
async def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    Register a new user and return an access token.

    Parameters
    ----------
    username : str
        The username of the user.
    email : str
        The email of the user.
    password : str
        The password of the user.
    confirm_password : str
        The confirmation of the password.
    db : Session
        The current database session.

    Returns
    -------
    Token
        The access token with user uuid and permission.
    """
    validate_password(password)
    if password != confirm_password:
        raise HTTPException(
            status_code=400, detail="Passwords do not match")
    user_new = await create_user(db, UserCreate(username=username, email=email, password=password))
    return create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=user_new.uuid,
            permission=user_new.permission
        ))


@router.post("/OTP", response_model=Token)
def login_otp(
    otp_code: str | int = Query(...),
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
async def get_otp_qr(current_user: UserReadDB = Depends(get_current_user)):
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
    uri, secret = await generate_otp(
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
async def verify_email(token: str, db: Session = Depends(get_db)):
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
    user = await update_user(db, user.uuid, UserUpdate(email_verified=True))
    return RedirectResponse(url=settings.FRONTEND_URL)


@router.patch("/password/reset", response_class=Response)
async def reset_password(
    old_password: str = Form(...), new_password: str = Form(...), confirm_password: str = Form(...),
    db: Session = Depends(get_db), current_user: UserReadDB = Depends(get_current_user)
):
    """
    Reset a user's password by its old password and new password.

    Parameters
    ----------
    old_password : str
        The old password of the user.
    new_password : str
        The new password of the user.
    confirm_new_password : str
        The confirmation of the new password.
    db : Session
        The current database session.
    current_user : UserReadDB
        The user object of the user who is making the request.

    Returns
    -------
    RedirectResponse
        A redirect to the frontend URL.

    Raises
    ------
    HTTPException
        400 Bad Request if the new password is the same as the old password or if the passwords do not match.
        401 Unauthorized if the old password is invalid.
    """
    validate_password(new_password)
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if old_password == new_password:
        raise HTTPException(
            status_code=400, detail="New password cannot be the same as old password")
    if not verify_password(old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid password")
    await update_user(db, current_user.uuid, UserUpdate(password=new_password))
    return Response(content="Password reset successful", status_code=200)


@router.get("/token/validate")
def validate_token(current_user: UserReadDB = Depends(get_current_user)):
    """
    Validate the current user's token.

    Parameters
    ----------
    current_user : UserReadDB
        The current user object.

    Returns
    -------
    Response
        A response with the content "ValidToken" if the token is valid.
    """
    return Response(content="ValidToken | " + current_user.uuid)
