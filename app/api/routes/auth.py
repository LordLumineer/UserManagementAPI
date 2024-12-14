"""
Authentication logic for the API.

This module contains the authentication logic for the API. It includes
the routes for logging in and out, as well as the routes for generating
and verifying the One-Time-Password (OTP) QR code.
"""
from io import BytesIO
from typing import Literal
from fastapi import APIRouter, Request
from fastapi.exceptions import HTTPException
from fastapi.params import Depends, Form, Header, Query
from fastapi.responses import RedirectResponse, Response
from fastapi.security import OAuth2PasswordRequestFormStrict
from pydantic import BaseModel
import qrcode
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import get_async_db
from app.core.email import send_reset_password_email
from app.db_objects.user import (
    get_current_user, get_user, get_user_by_email, get_user_by_username,
    create_user, update_user
)
from app.core.security import (
    Token, TokenData,
    authenticate_user, decode_access_token, validate_otp,
    create_access_token, generate_otp, verify_password
)
from app.core.utils import validate_email, validate_password
from app.db_objects.db_models import User as User_DB
from app.templates.schemas.user import UserCreate, UserRead, UserUpdate, UserHistory


router = APIRouter()


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestFormStrict = Depends(),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Login user and return an access token.

    Parameters
    ----------
    form_data : OAuth2PasswordRequestForm
        Form with username and password.

    Returns
    -------
    Token
        access token with user uuid and roles.
    """
    user = await authenticate_user(
        db=db, username=form_data.username, password=form_data.password, request=request)
    return create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=user.uuid,
            roles=user.roles
        ))


@router.post("/logout", response_class=Response)
def logout(request: Request, current_user: User_DB = Depends(get_current_user)):
    """
    Logout user and return a response.

    Parameters
    ----------
    current_user : User_DB
        The current user object.

    Returns
    -------
    Response
        A response with a status code of 200 if the user is logged out successfully,
        or a response with a status code of 401 if there is an error.
    """
    request.session.clear()
    return Response(content=f"{current_user.username} | Logged out", status_code=200)


class _SignupForm(BaseModel):
    username: str
    email: str
    password: str
    confirm_password: str


@router.post("/register", response_model=Token)
async def register(
    signup_form: _SignupForm = Form(...),
    db: AsyncSession = Depends(get_async_db),
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
        The access token with user uuid and roles.
    """
    validate_password(signup_form.password)
    if signup_form.password != signup_form.confirm_password:
        raise HTTPException(
            status_code=400, detail="Passwords do not match")
    user_new = await create_user(db,
                                 UserCreate(
                                     username=signup_form.username,
                                     email=signup_form.email,
                                     password=signup_form.password
                                 ))
    return create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=user_new.uuid,
            roles=user_new.roles
        ))


@router.post("/OTP", response_model=Token)
async def login_otp(
    request: Request,
    otp_code: str | int = Query(...),
    db: AsyncSession = Depends(get_async_db),
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
        access token with user uuid and roles.

    Raises
    ------
    HTTPException
        401 Unauthorized if the OTP code is invalid or OTP is not enabled.
    """
    otp_token = request.session.get("otp_token")
    if not otp_token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    token_data = decode_access_token(otp_token)
    if token_data.purpose != "OTP":
        raise HTTPException(status_code=401, detail="Unauthorized")
    db_user = await get_user(db, token_data.uuid)
    if db_user.uuid != token_data.uuid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if db_user.otp_method == "none":
        raise HTTPException(status_code=401, detail="OTP not enabled")
    if not validate_otp(
        user_username=db_user.username,
        user_otp_secret=db_user.otp_secret,
        otp=otp_code,
        method=db_user.otp_method
    ):
        raise HTTPException(status_code=401, detail="Invalid OTP code")
    return create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=db_user.uuid,
            roles=db_user.roles
        ))


@router.patch("/OTP/{method}", response_model=UserRead)
async def change_otp_method(
    method: Literal['authenticator', 'email', 'none'],
    otp_code: str | int = Query(...),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Change the OTP method for the current user.

    Parameters
    ----------
    method : Literal['authenticator', 'email', 'none']
        The new OTP method to set for the user.
    otp_code : str | int
        The OTP code to validate the change.
    current_user : User_DB
        The current user object.
    db : Session
        The current database session.

    Returns
    -------
    UserRead
        The updated user object with the new OTP method.

    Raises
    ------
    HTTPException
        401 Unauthorized if the OTP code is invalid.
    IntegrityError
        If there is an error during the database transaction.
    """
    current_user.otp_method = method
    if method != "none":
        if not validate_otp(
            user_username=current_user.username,
            user_otp_secret=current_user.otp_secret,
            otp=otp_code,
            method=method
        ):
            raise HTTPException(status_code=401, detail="Invalid OTP code")
    db.add(current_user)
    await db.commit()
    await db.refresh(current_user)

    return current_user


@router.get("/QR", response_class=Response)
async def get_otp_qr(current_user: User_DB = Depends(get_current_user), db: AsyncSession = Depends(get_async_db)):
    """
    Generate a QR code with the user's OTP URI and return it as an image.

    Parameters
    ----------
    current_user : User_DB
        The user who is requesting the QR code.

    Returns
    -------
    Response
        An HTTP response with the QR code image.
    """
    uri, secret = await generate_otp(
        db, current_user.uuid, current_user.username, current_user.otp_secret)
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
async def verify_email(token: str, db: AsyncSession = Depends(get_async_db)):
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
    db_user = await get_user_by_email(db, token_data.email)
    if db_user.uuid != token_data.uuid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    await update_user(db, db_user, UserUpdate(email_verified=True, action=UserHistory(
        action="email-verified",
        description=f"Email {db_user.email} verified",
        by=db_user.username
    )))
    return RedirectResponse(url=settings.FRONTEND_URL)


@router.get("/forgot-password/request", response_class=Response)
async def forgot_password_request(
    request: Request,
    username: str = Query(...),
    email: str = Query(...),
    db: AsyncSession = Depends(get_async_db),
):
    """
    Request a password reset for the given username and email.

    Parameters
    ----------
    username : str
        The username of the user.
    email : str
        The email of the user.
    db : Session
        The current database session.

    Returns
    -------
    Response
        A response with no content.

    Raises
    ------
    HTTPException
        401 Unauthorized if the user is not authorized to request a password reset.
    """
    email = validate_email(email)
    db_user = await get_user_by_username(db, username)
    if db_user.email != email or username != db_user.username or not db_user.is_active:
        raise HTTPException(status_code=401, detail="Unauthorized")

    db_user = await update_user(db, db_user, UserUpdate(
        is_active=False,
        action=UserHistory(
            action="Forgot password request",
            description=f"The user ({
                db_user.username}) has requested a password reset while logged OUT.",
            by="<logged out user>"
        )))

    token = create_access_token(
        sub=TokenData(
            purpose="reset-password",
            uuid=db_user.uuid,
            username=db_user.username
        ))
    return await send_reset_password_email(db_user.email, token, "/forgot-password/reset-form", request)


@router.get("/forgot-password/reset", response_class=Response)
async def forgot_password_reset(
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    authorization_header: str = Header(...),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Reset the user's password using a reset token.

    Parameters
    ----------
    new_password : str
        The new password for the user.
    confirm_password : str
        The confirmation of the new password.
    authorization_header : str
        The authorization header containing the reset password token.
    db : Session
        The database session.

    Returns
    -------
    Response
        A response with a status code of 200 if the password is reset successfully.

    Raises
    ------
    HTTPException
        401 Unauthorized if the token is invalid or if the user is unauthorized.
    HTTPException
        400 Bad Request if the passwords do not match or if the new password is the
        same as the old password.
    """
    token_data = decode_access_token(authorization_header)
    if token_data.purpose != "reset-password":
        raise HTTPException(status_code=401, detail="Unauthorized")
    db_user = await get_user_by_username(db, token_data.username)
    if db_user.uuid != token_data.uuid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    validate_password(new_password)
    if new_password != confirm_password:
        raise HTTPException(
            status_code=400, detail="Passwords do not match")
    if verify_password(new_password, db_user.hashed_password):
        raise HTTPException(
            status_code=400, detail="New password cannot be the same as old password")

    db_user = await update_user(db, db_user, UserUpdate(
        password=new_password,
        is_active=True,
        action=UserHistory(
            action="Forgot password Reset",
            description=f"The user ({
                db_user.username}) has Successfully reset their forgotten password.",
            by="<logged out user>"
        )))
    return Response(content="Password reset successful", status_code=200)


class _ResetPasswordForm(BaseModel):
    old_password: str
    new_password: str
    confirm_password: str


@router.get("/password/reset", response_class=Response)
async def request_password_request(
    request: Request,
    current_user: User_DB = Depends(get_current_user)
):
    """
    Request a password reset for the current user.

    Parameters
    ----------
    current_user : User_DB
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
    return await send_reset_password_email(current_user.email, token, "/reset-password", request)


@router.patch("/password/reset", response_class=Response)
async def reset_password_reset(
    reset_password_form: _ResetPasswordForm = Form(...),
    authorization_header: str = Header(...),
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Reset the password of the current user.

    Parameters
    ----------
    reset_password_form : _ResetPasswordForm
        The form containing the old password, new password, and confirmation of the new password.
    authorization_header : str
        The authorization header containing a valid reset password token.
    current_user : User_DB
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
    db_user = await get_user_by_username(db, token_data.username)
    if db_user.uuid != token_data.uuid or db_user.uuid != current_user.uuid:
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
    await update_user(db, current_user.uuid, UserUpdate(
        password=reset_password_form.new_password,
        action=UserHistory(
            action="Password Reset",
            description=f"Password reset for {db_user.username}",
            by=current_user.uuid
        )))
    return Response(content="Password reset successful", status_code=200)


@router.get("/token/validate")
def validate_token(current_user: User_DB = Depends(get_current_user)):
    """
    Validate the current user's token.

    Parameters
    ----------
    current_user : User_DB
        The current user object.

    Returns
    -------
    Response
        A response with the content "ValidToken" if the token is valid.
    """
    return Response(content="ValidToken | " + current_user.uuid)
