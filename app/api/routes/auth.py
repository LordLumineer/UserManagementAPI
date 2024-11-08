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
from fastapi.params import Depends, Form, Header, Query
from fastapi.responses import RedirectResponse, Response
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import qrcode
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.email import send_reset_password_email
from app.core.object.user import (
    get_current_user, get_user, get_user_by_email, get_user_by_username,
    create_user, update_user
)
from app.core.security import (
    Token, TokenData,
    authenticate_user, decode_access_token, validate_otp,
    create_access_token, generate_otp, verify_password
)
from app.core.utils import validate_password
from app.templates.models import User as User_Model
from app.templates.schemas.user import UserCreate, UserUpdate


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
def logout(current_user: User_Model = Depends(get_current_user)):
    """
    Logout user and return a response.

    Parameters
    ----------
    current_user : User_Model
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
    if user.uuid != token_data.uuid:
        raise HTTPException(status_code=401, detail="Unauthorized")
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
async def get_otp_qr(current_user: User_Model = Depends(get_current_user)):
    """
    Generate a QR code with the user's OTP URI and return it as an image.

    Parameters
    ----------
    current_user : User_Model
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


@router.get("/password/reset", response_class=Response)
async def request_password_reset(current_user: User_Model = Depends(get_current_user)):
    """
    Request a password reset for the current user.

    Parameters
    ----------
    current_user : User_Model
        The current user.

    Returns
    -------
    Response
        A response with no content.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to request a password reset.
    """
    token = create_access_token(
        sub=TokenData(
            purpose="reset-password",
            uuid=current_user.uuid,
            username=current_user.username
        ))
    return await send_reset_password_email(current_user.email, token)


class _ResetPasswordForm(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str


@router.patch("/password/reset", response_class=Response)
async def reset_password(
    reset_password_form: _ResetPasswordForm = Form(...),
    authorization_header: str = Header(...),
    current_user: User_Model = Depends(get_current_user), db: Session = Depends(get_db)
):
    """
    Reset the password of the current user.

    Parameters
    ----------
    reset_password_form : _ResetPasswordForm
        The form containing the old password, new password, and confirmation of the new password.
    authorization_header : str
        The authorization header containing a valid reset password token.
    current_user : User_Model
        The current user object.
    db : Session
        The current database session.

    Returns
    -------
    Response
        A response with a status code of 200 if the password is reset successfully.

    Raises
    ------
    HTTPException
        401 Unauthorized if the token is invalid.
    HTTPException
        400 Bad Request if the passwords do not match, 
            or if the new password is the same as the old password, 
            or if the old password is invalid.
    """
    token_data = decode_access_token(authorization_header)
    if token_data.purpose != "reset-password":
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = get_user_by_username(db, token_data.username)
    if user.uuid != token_data.uuid or user.uuid != current_user.uuid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    validate_password(reset_password_form.new_password)
    if reset_password_form.new_password != reset_password_form.confirm_password:
        raise HTTPException(
            status_code=400, detail="Passwords do not match")
    if reset_password_form.old_password == reset_password_form.new_password:
        raise HTTPException(
            status_code=400, detail="New password cannot be the same as old password")
    if not verify_password(reset_password_form.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid password")
    await update_user(db, current_user.uuid, UserUpdate(password=reset_password_form.new_password))
    return Response(content="Password reset successful", status_code=200)


@router.get("/token/validate")
def validate_token(current_user: User_Model = Depends(get_current_user)):
    """
    Validate the current user's token.

    Parameters
    ----------
    current_user : User_Model
        The current user object.

    Returns
    -------
    Response
        A response with the content "ValidToken" if the token is valid.
    """
    return Response(content="ValidToken | " + current_user.uuid)
