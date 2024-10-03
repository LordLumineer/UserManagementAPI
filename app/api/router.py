from fastapi import APIRouter

from app.api.routes import (
    db,
    file,
    login,
    user,
)


api_router = APIRouter()
api_router.include_router(login.router, prefix="/login", tags=["Login"])
api_router.include_router(file.router, prefix="/file", tags=["File"])
api_router.include_router(user.router, prefix="/user", tags=["User"])


api_router.include_router(db.router, prefix="/db", tags=["Database"])
