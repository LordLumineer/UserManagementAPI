from io import BytesIO
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.params import Query, Header
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
import qrcode
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.object.user import get_current_user, get_user, get_user_by_email, update_user
from app.core.security import Token, TokenData, authenticate_user, create_access_token, decode_access_token, generate_otp, validate_otp
from app.templates.schemas.user import UserReadDB, UserUpdate


router = APIRouter()


@router.post("/login", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = await authenticate_user(
        db=db, username=form_data.username, password=form_data.password, request=request)
    return create_access_token(
        sub=TokenData(
            uuid=user.uuid,
            permission=user.permission
        )
    )


@router.post("/2FA", response_model=Token)
def login_2FA(
    otp_code: str = Query(),
    authorization_header: str = Header(),
    db: Session = Depends(get_db)
):
    if not authorization_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization")
    otp_token_claims = decode_access_token(
        authorization_header.replace("Bearer ", ""))
    user = get_user(db, otp_token_claims["sub"]["uuid"])
    if user.otp_method == "none":
        raise HTTPException(status_code=401, detail="2FA not enabled")
    if not validate_otp(
        user_username=user.username,
        user_otp_secret=user.otp_secret,
        otp=otp_code,
        method=user.otp_method
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


@router.get("/email/verify", response_class=RedirectResponse)
def verify_email(token: str, db: Session = Depends(get_db)):
    token_claims = decode_access_token(token.replace("Bearer ", ""))
    user = get_user_by_email(db, token_claims["sub"]["email"])
    if user.uuid != token_claims["sub"]["uuid"]:
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = update_user(db, user.uuid, UserUpdate(email_verified=True))
    return RedirectResponse(url=settings.FRONTEND_URL)
