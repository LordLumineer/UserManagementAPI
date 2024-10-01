from datetime import datetime, timedelta, timezone
from authlib.jose import jwt
import bcrypt
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import pyotp

from app.core.config import settings
from app.core.utils import generate_random_letters


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


# import pyotp
# import qrcode


# secret = "Q3OBRIQFU4YMF6SR6SOJXLQA3ZIQWRF4"
# # print(secret)

# totp = pyotp.TOTP(
#     s=secret,
#     name="accountName",
#     issuer="issuerName"
# )
# print("Current OTP:", totp.now())

# uri = totp.provisioning_uri()
# print("URI:", uri)

# qrcode.make(uri).save("qrcode.png")

def generate_otp(user_uuid: str, user_username: str, user_otp_secret: str) -> tuple[str, str]:
    if not user_otp_secret:
        secret = generate_random_letters(length=32, seed=user_uuid)
        # TODO: save secret in database
    totp = pyotp.TOTP(
        s=user_otp_secret,
        name=user_username,
        issuer=settings.PROJECT_NAME
    )
    uri = totp.provisioning_uri()
    secret = totp.secret
    return uri, secret


def validate_otp(user_username: str, user_otp_secret: str, otp: str) -> bool:
    if not user_otp_secret:
        return False
    totp = pyotp.TOTP(
        s=user_otp_secret,
        name=user_username,
        issuer=settings.PROJECT_NAME
    )
    return totp.verify(otp)
