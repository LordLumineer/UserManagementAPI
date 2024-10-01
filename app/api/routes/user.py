from io import BytesIO
from fastapi import APIRouter, Depends
from fastapi.responses import Response
import qrcode

from app.core.object.user import get_current_user
from app.core.security import generate_otp
from app.templates.schemas.user import UserRead, UserReadDB


router = APIRouter()


# @router.get("/")
# def test_QR(current_user: UserReadDB = Depends(get_current_user)):
#     print(current_user)
#     #uri, secret = generate_otp(current_user.uuid, current_user.username, current_user.otp_secret)
#     uri = "test"
#     qr = qrcode.make(uri)
#     img_io = BytesIO()
#     qr.save(img_io, 'PNG')
#     return Response(
#         content=img_io.getvalue(),
#         headers={'secret': 'super secrets'},
#         media_type="image/png"
#     )


@router.get("/")
def test_QR(current_user: UserReadDB = Depends(get_current_user)):
    uri, secret = generate_otp(current_user.uuid, current_user.username, current_user.otp_secret)
    qr = qrcode.make(uri)
    img_io = BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    return Response(
        content=img_io.getvalue(),
        headers={'secret': secret},
        media_type="image/png"
    )
