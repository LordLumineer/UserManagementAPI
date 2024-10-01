from io import BytesIO
from fastapi import APIRouter
from fastapi.responses import Response
import qrcode


router = APIRouter()


@router.get("/")
def test_QR():
    uri = "qwerty"
    print("1")
    qr = qrcode.make(uri)
    print("2")
    img_io = BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    print("3")
    return Response(
        content=img_io.getvalue(),
        headers={'secret': 'super secrets'},
        media_type="image/png"
    )
