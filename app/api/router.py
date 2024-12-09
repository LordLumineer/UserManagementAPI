"""
Main API router for the application

This module contains the main API router for the application. It includes all
the routes for the application, including the authentication, user, file, db
and email routes.
"""
from fastapi import APIRouter

from app.api.routes import (
    auth,
    oauth,
    db,
    email,
    file,
    user,
    admin,
    provider_router,
)


api_router = APIRouter()
api_router.include_router(admin.router, prefix="/admin", tags=["Admin"])
# Important
api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
api_router.include_router(oauth.router, prefix="/oauth", tags=["OAuth2"])
# Main Functions
api_router.include_router(user.router, prefix="/user", tags=["User"])
# Secondary Functions
api_router.include_router(file.router, prefix="/file", tags=["File"])
# Management
api_router.include_router(db.router, prefix="/db", tags=["Database"])
api_router.include_router(email.router, prefix="/email", tags=["Email"])

api_router.include_router(provider_router.router, prefix="/providers", tags=["Providers"])

tags_metadata = [
    {
        "name": "Auth",
        "description": "The **Authentication** logic is implemented here.",
    }, {
        "name": "OAuth2",
        "description": "The **OAuth2** logic to login/register with third-party providers is implemented here.",
    }, {
        "name": "User",
        "description": "The **User** logic (CRUD operations) is implemented here.",
    }, {
        "name": "File",
        "description": "The **Files** logic (CRUD operations) is implemented here.",
    }, {
        "name": "Database",
        "description": "The **Database** logic is implemented here. It is only accessible to admins.",
    }, {
        "name": "Email",
        "description": "The **Email** logic is implemented here. It is only accessible to admins.",
    }, {
        "name": "Admin",
        "description": "The **Admin** Control Panel is implemented here. It is only accessible to admins.",
    }
]
tags_metadata.extend(provider_router.tags_metadata)
