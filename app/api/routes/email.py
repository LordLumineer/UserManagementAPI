from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.params import Query

from app.core.db import get_db
from app.core.email import send_email, send_test_email
from app.core.object.user import get_current_user, get_users
from app.templates.schemas.user import UserReadDB


router = APIRouter()


@router.post("/send-test-email")
async def test_email(recipient: str = "lordlumineeralt@gmail.com", current_user: UserReadDB = Depends(get_current_user)):
    if current_user.permission != "admin":
        raise HTTPException(status_code=401, detail="Unauthorized")
    return await send_test_email(recipient)

@router.post("/send-email")
async def send_email_single(
    confirm: bool = Query(default=False),
    subject: str = Query(),
    recipient: str = Query(),
    content: str = Form(),
    current_user: UserReadDB = Depends(get_current_user)
):
    if not current_user.permission in ["manager", "admin"] or not confirm:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return await send_email([recipient], subject, content)

@router.post("/send-email-multiple")
async def send_email_multiple(
    confirm: bool = Query(default=False),
    subject: str = Query(),
    recipients: list[str] = Query(),
    content: str = Form(),
    current_user: UserReadDB = Depends(get_current_user)
):
    if not current_user.permission in ["manager", "admin"] or not confirm:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return await send_email(recipients, subject, content)


@router.post("/send-email-all")
async def send_email_all(
    confirm: bool = Query(default=False),
    subject: str = Query(),
    content: str = Form(),
    current_user: UserReadDB = Depends(get_current_user)
):
    if not current_user.permission in ["admin"] or not confirm:
        raise HTTPException(status_code=401, detail="Unauthorized")
    db = next(get_db())
    try:
        users = get_users(db)
    finally:
        db.close()
    recipients = [user.email for user in users]
    return await send_email(recipients, subject, content)
