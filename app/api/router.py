from fastapi import APIRouter

from app.api.routes import (
    login,
    user
)


api_router = APIRouter()
api_router.include_router(login.router, prefix="/login", tags=["Login"])
api_router.include_router(user.router, prefix="/user", tags=["User"])
