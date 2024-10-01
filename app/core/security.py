from datetime import datetime, timedelta, timezone
from authlib.jose import jwt
import bcrypt
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from app.core.config import settings


ALGORITHM = settings.JWT_ALGORITHM
SECRET_KEY = settings.JWT_SECRET_KEY
ACCESS_TOKEN_EXPIRE_MINUTES = settings.JWT_EXP

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.BASE_URL}{settings.API_STR}/login",
    auto_error=True
)


class TokenData(BaseModel):
    """
    Represents a user's token data.

    Attributes:
        uuid (str): The user's uuid.
        role (str): The user's role.
    """
    uuid: str
    permition: str


def hash_password(password: str) -> str:
    try:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    except UnicodeEncodeError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be a string. {e.reason}",
        ) from e
    return hashed.decode("utf-8")


def decode_access_token(token: str, key: str = SECRET_KEY):
    try:
        claims = jwt.decode(token, key)
    except (Exception, not claims) as e:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
        ) from e
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
    claims["sub"] = TokenData(
        **dict(item.split("=") for item in claims["sub"].replace("'", "").split())
    )
    return claims
