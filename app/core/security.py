from datetime import datetime, timedelta, timezone
import json
from tkinter import E
from authlib.jose import jwt
from authlib.jose.errors import DecodeError
import bcrypt
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import pyotp
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.utils import generate_random_letters, validate_email


ALGORITHM = settings.JWT_ALGORITHM
SECRET_KEY = settings.JWT_SECRET_KEY
ACCESS_TOKEN_EXPIRE_MINUTES = settings.JWT_EXP


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.BASE_URL}{settings.API_STR}/login/",
    auto_error=True
)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    uuid: str
    permission: str


def hash_password(password: str) -> str:
    try:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    except UnicodeEncodeError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be a string. {e.reason}",
        ) from e
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(
    sub: TokenData,
    exp: timedelta = ACCESS_TOKEN_EXPIRE_MINUTES,
    key: str = SECRET_KEY
):
    headers = {"alg": ALGORITHM, "token_type": "bearer"}
    payload = {
        "iss": settings.PROJECT_NAME,
        "sub": jsonable_encoder(sub),
        "exp": str(int(timedelta(minutes=exp).total_seconds())),
        "iat": str(int(datetime.now(timezone.utc).timestamp())),
    }
    encoded_jwt = jwt.encode(headers, payload, key)
    return Token(access_token=encoded_jwt, token_type="bearer")


def decode_access_token(token: str, key: str = SECRET_KEY):
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
        claims["sub"] = json.loads(str(claims["sub"]).replace("'", '"'))
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid token. {e}",
        ) from e
    return claims


def generate_otp(user_uuid: str, user_username: str, user_otp_secret: str) -> tuple[str, str]:
    if not user_otp_secret:
        from app.templates.schemas.user import UserUpdate  # pylint: disable=import-outside-toplevel
        from app.core.object.user import update_user  # pylint: disable=import-outside-toplevel
        db = next(get_db())
        try:
            secret = generate_random_letters(length=32, seed=user_uuid)
            updated_user = UserUpdate(
                otp_secret=secret
            )
            user = update_user(db=db, uuid=user_uuid, user=updated_user)
        finally:
            db.close()
    totp = pyotp.TOTP(
        s=user_otp_secret,
        name=user_username,
        issuer=settings.PROJECT_NAME
    )
    uri = totp.provisioning_uri()
    secret = totp.secret
    return uri, secret


def validate_otp(user_username: str, user_otp_secret: str, otp: str, method: str) -> bool:
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


def authenticate_user(db: Session, username: str, password: str):
    from app.core.object.user import get_user_by_email, get_user_by_username  # pylint: disable=import-outside-toplevel

    error_msg = HTTPException(
        status_code=401,
        detail="Incorrect username/email or password or email not verified",
        headers={"WWW-Authenticate": "Bearer"},
    )
    # if username in ["user", "manager", "admin"]: # TODO: remove comments
    #     raise error_msg
    try:
        if username == "admin@example.com":
            username = "admin"
        email = validate_email(username)
        user = get_user_by_email(db=db, email=email)
        if not user.email_verified:
            raise error_msg
    except HTTPException:
        user = get_user_by_username(db=db, username=username)
    if not user:
        raise error_msg
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user, please contact admin")

    if verify_password(password, user.hashed_password):
        if user.otp_method == "none":
            return user
        
        if user.otp_method == "email":
            # TODO: Send OTP email
            pass
        
        otp_request_token = create_access_token(
            sub={
                "uuid": user.uuid,
            })
        raise HTTPException(
            status_code=401,
            detail=jsonable_encoder({
                "message": "Please enter OTP",
                "method": user.otp_method,
                "curl": {
                    "-X": "POST",
                    "url": f"{settings.BASE_URL}{settings.API_STR}/login/2FA?otp_code=",
                    "-H": f"Authorization: {otp_request_token.token_type} {otp_request_token.access_token}",
                    "-d": ""
                }
            }),
        )
    raise error_msg
