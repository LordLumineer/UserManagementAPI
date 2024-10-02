from io import BytesIO
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
import qrcode
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.object.user import get_current_user, get_user
from app.core.security import Token, TokenData, authenticate_user, create_access_token, decode_access_token, generate_otp, validate_otp
from app.templates.schemas.user import UserReadDB


router = APIRouter()


@router.post("/", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(
        db=db, username=form_data.username, password=form_data.password)
    return create_access_token(
        sub=TokenData(
            uuid=user.uuid,
            permission=user.permission
        )
    )


@router.post("/2FA", response_model=Token)
def login_2FA(otp_code: str, otp_request_token: str, db: Session = Depends(get_db)):
    otp_token_claims = decode_access_token(otp_request_token)
    user = get_user(db, otp_token_claims["sub"]["uuid"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.otp_enabled:
        raise HTTPException(status_code=401, detail="2FA not enabled")
    if not validate_otp(
        user_username=user.username,
        user_otp_secret=user.otp_secret,
        otp=otp_code
    ):
        raise HTTPException(status_code=401, detail="Invalid OTP code")
    return create_access_token(
        sub=TokenData(
            uuid=user.uuid,
            permission=user.permission
        )
    )


@router.get("/QR", response_class=Response)
def test_QR(current_user: UserReadDB = Depends(get_current_user)):
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
