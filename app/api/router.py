from fastapi import APIRouter

from app.api.routes import (
    db,
    email,
    file,
    login,
    user,
)


api_router = APIRouter()
# Important
api_router.include_router(login.router, prefix="/login", tags=["Login"])
# Main Functions
api_router.include_router(user.router, prefix="/user", tags=["User"])
# Secondary Functions
api_router.include_router(file.router, prefix="/file", tags=["File"])
# Management
api_router.include_router(db.router, prefix="/db", tags=["Database"])
api_router.include_router(email.router, prefix="/email", tags=["Email"])
