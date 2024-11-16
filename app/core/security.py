"""
Security utilities for the API.

This module contains the utilities for the authentication and authorization
of the API. It includes the functions to hash passwords, generate and verify
the JSON Web Tokens (JWT) and the One-Time-Password (OTP) QR code.
"""
from datetime import datetime, timedelta, timezone
import re
from typing import Literal, Self
from authlib.jose import jwt
from authlib.jose.errors import DecodeError
import bcrypt
from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ValidationError, model_validator
import pyotp
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings, logger
from app.core.email import send_otp_email
from app.core.utils import generate_random_letters, validate_email


ALGORITHM = settings.JWT_ALGORITHM
SECRET_KEY = settings.JWT_SECRET_KEY
ACCESS_TOKEN_EXPIRE_MINUTES = settings.JWT_EXP


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.BASE_URL}{settings.API_STR}/auth/login",
    auto_error=True
)


class Token(BaseModel):
    """
    A token returned from the authentication endpoint.

    Attributes
    ----------
    access_token : str
        The actual token to use in the Authorization header.
    token_type : str
        The type of the token, either Bearer or JWT.
    """
    access_token: str
    token_type: str

    def __str__(self) -> str:
        return f"{self.token_type} {self.access_token}"


class TokenData(BaseModel):
    """
    The data encoded in a JSON Web Token (JWT).

    Attributes
    ----------
    purpose : Literal["login", "reset-password", "email-verification", "OTP"]
        The purpose of the token.
    uuid : str
        The UUID of the user.
    permission : str | None
        The permission of the user, if purpose is "login".
    email : str | None
        The email of the user, if purpose is "email-verification".
    username : str | None
        The username of the user, if purpose is "reset-password".
    """
    purpose: Literal["login", "reset-password", "email-verification", "OTP"]
    uuid: str
    permission: str | None = None
    email: str | None = None
    username: str | None = None

    @model_validator(mode="after")
    def _enforce_data(self) -> Self:
        match self.purpose:
            case "login":
                if self.permission is None:
                    raise ValueError("Missing permission")
            case "reset-password":
                if self.username is None:
                    raise ValueError("Missing username")
            case "email-verification":
                if self.email is None:
                    raise ValueError("Missing email")
            case "OTP":
                pass
            case _:
                raise ValueError(f"Invalid purpose: {self.purpose}")

        return self


def hash_password(password: str) -> str:
    """
    Hashes a password using bcrypt.

    :param str password: The password to hash.
    :return str: The hashed password.

    :raises HTTPException: If the password is not a string.
    """
    try:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    except UnicodeEncodeError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be a string. {e.reason}",
        ) from e
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a password against a hashed password using bcrypt.

    :param str plain_password: The password to verify.
    :param str hashed_password: The hashed password to compare with.
    :return bool: True if the password matches the hash, False otherwise.

    :raises HTTPException: If the password is not a string.
    """
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(
    sub: TokenData,
    exp: timedelta = ACCESS_TOKEN_EXPIRE_MINUTES,
    key: str = SECRET_KEY
) -> Token:
    """
    Creates an access token for a given subject.

    :param TokenData sub: The subject to encode in the token.
    :param timedelta, optional exp: The time to live of the token in minutes.
    :param str, optional key: The secret key to use for encoding.
    :return Token: The encoded token.
    """
    headers = {"alg": ALGORITHM, "token_type": "bearer"}
    payload = {
        "iss": settings.PROJECT_NAME,
        "sub": jsonable_encoder(sub),
        "exp": str(int(timedelta(minutes=exp).total_seconds())),
        "iat": str(int(datetime.now(timezone.utc).timestamp())),
    }
    encoded_jwt = jwt.encode(headers, payload, key)
    return Token(access_token=encoded_jwt, token_type="bearer")


def decode_access_token(token: str, strict: bool = True, key: str = SECRET_KEY) -> TokenData:
    """
    Decodes a JSON Web Token (JWT) based on the given token, strictness, and secret key.

    :param str token: The JWT to decode.
    :param bool strict: If True, the token must start with "Bearer " or an HTTPException will be raised.
    :param str key: The secret key used to decode the JWT. Defaults to SECRET_KEY.
    :return TokenData: The decoded JWT data, which is a TokenData object containing the user's UUID and permission.

    :raises HTTPException: If the token is invalid, expired, or has an invalid issuer.
    """
    if strict:
        # token.startswith("bearer "):
        if not bool(re.match('bearer', token, re.I)):
            raise HTTPException(
                status_code=401, detail="Invalid authorization")
    insensitive_token = re.compile(re.escape("bearer "), re.IGNORECASE)
    token = insensitive_token.sub("", token)  # token.replace("bearer ", "")
    try:
        claims = jwt.decode(token, key)
    except DecodeError as e:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid token. {e}",
        ) from e
    if not claims:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
        )
    if claims["iss"] != settings.PROJECT_NAME:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials | Invalid issuer",
        )
    iat = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
    iat = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
    if iat > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=401,
            detail="Token not yet valid",
        )
    exp = timedelta(seconds=int(claims["exp"]))
    if iat + exp < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=401,
            detail="Token expired",
        )
    try:
        return TokenData(**claims["sub"])
    except ValidationError as e:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid token. {e}",
        ) from e


async def generate_otp(
    db: Session,
    user_uuid: str,
    user_username: str,
    user_otp_secret: str | None = None
) -> list[str, str]:
    """
    Generate a new OTP URI and secret for a user.

    If the user does not have an OTP secret, one is generated and stored in the user object.

    :param str user_uuid: The UUID of the user.
    :param str user_username: The username of the user.
    :param str user_otp_secret: The OTP secret of the user if it exists.
    :return tuple[str, str]: A tuple of the OTP URI and secret.
    """
    if not user_otp_secret or user_otp_secret == "changeme":
        from app.db_objects.db_models import User as User_DB  # pylint: disable=import-outside-toplevel
        user_otp_secret = generate_random_letters(
            length=32, seed=user_uuid)
        try:
            user_db = db.query(User_DB).filter(
                User_DB.uuid == user_uuid).first()
            user_db.otp_secret = user_otp_secret
            db.add(user_db)
            db.commit()
            db.refresh(user_db)
        except IntegrityError as e:
            db.rollback()
            raise e
    totp = pyotp.TOTP(
        s=user_otp_secret,
        name=user_username,
        issuer=settings.PROJECT_NAME
    )
    uri = totp.provisioning_uri()
    secret = totp.secret
    return uri, secret


def validate_otp(user_username: str, user_otp_secret: str, otp: str, method: str) -> bool:
    """
    Validate a one-time password (OTP) against a user's secret and chosen method.

    :param str user_username: The username of the user.
    :param str user_otp_secret: The OTP secret of the user.
    :param str otp: The one-time password provided by the user.
    :param str method: The method the user chose to use for OTP verification.
    :return bool: True if the OTP is valid, False if it is not.
    """
    if not user_otp_secret:
        return False
    match method:
        case "none":
            return True
        case "authenticator":
            totp = pyotp.TOTP(
                s=user_otp_secret,
                name=user_username,
                interval=settings.OTP_AUTHENTICATOR_INTERVAL,
                issuer=settings.PROJECT_NAME,
                digits=settings.OTP_LENGTH
            )
            return totp.verify(otp)
        case "email":
            totp = pyotp.TOTP(
                s=user_otp_secret,
                name=user_username,
                interval=settings.OTP_EMAIL_INTERVAL,
                issuer=settings.PROJECT_NAME,
                digits=settings.OTP_LENGTH
            )
            return totp.verify(otp)
        case _:
            raise HTTPException(
                status_code=401,
                detail="Invalid OTP method"
            )


async def authenticate_user(db: Session, username: str, password: str, request: Request = None):
    """
    Authenticate a user using their username/email and password.

    :param Session db: The database session.
    :param str username: The username or email of the user.
    :param str password: The password of the user.
    :param Request request: The Request object, defaults to None.
    :raises HTTPException: 401 Unauthorized if the user is not found or the password is incorrect.
    :raises HTTPException: 400 Bad Request if the user is inactive.
    :return UserReadDB: The user object if the user is found and the password is correct.
    """
    from app.db_objects.user import get_user_by_email, get_user_by_username  # pylint: disable=import-outside-toplevel

    error_msg = HTTPException(
        status_code=401,
        detail="Incorrect username/email or password or email not verified",
        headers={"WWW-Authenticate": "Bearer"},
    )
    # FIXME: remove comments to force first login with email
    # if username in ["user", "manager", "admin"]:
    #     raise error_msg
    if username == "admin@example.com":
        username = "admin"
    email = validate_email(username, raise_error=False)
    db_user = get_user_by_email(db=db, email=email, raise_error=False)
    if db_user and not db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="\n".join([
                f"Inactive user, please contact support at {settings.CONTACT_EMAIL}.",
                db_user.deactivated_reason
            ])
        )
    if not db_user:
        db_user = get_user_by_username(
            db=db, username=username, raise_error=False)
    if not db_user:
        raise error_msg
    if not db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="\n".join([
                f"Inactive user, please contact support at {settings.CONTACT_EMAIL}.",
                db_user.deactivated_reason
            ])
        )
    if verify_password(password, db_user.hashed_password):
        if db_user.otp_method == "none":
            return db_user

        if not db_user.otp_secret:
            logger.debug("Generating OTP for user %s", db_user.username)
            otp_secret = (await generate_otp(db, user_uuid=db_user.uuid, user_username=db_user.username))[1]
        else:
            otp_secret = db_user.otp_secret
        if db_user.otp_method == "email":
            totp = pyotp.TOTP(
                s=otp_secret,
                name=db_user.username,
                interval=settings.OTP_EMAIL_INTERVAL,
                issuer=settings.PROJECT_NAME,
                digits=settings.OTP_LENGTH
            )
            await send_otp_email(
                recipient=db_user.email,
                otp_code=totp.now(),
                request=request
            )

        otp_request_token = create_access_token(
            sub=TokenData(
                purpose="OTP",
                uuid=db_user.uuid
            ))
        raise HTTPException(
            status_code=401,
            detail=jsonable_encoder({
                "message": "Please enter OTP",
                "method": db_user.otp_method,
                "token": str(otp_request_token)
            }),
        )
    raise error_msg
