"""
Main API router for the application

This module contains the main API router for the application. It includes all
the routes for the application, including the authentication, user, file, db
and email routes.
"""
from fastapi import APIRouter

from app.api.routes.providers import (
    discord,
    google,
    twitch,
    github,
)


router = APIRouter()
router.include_router(discord.router, prefix="/discord", tags=["Discord"])
router.include_router(google.router, prefix="/google", tags=["Google"])
router.include_router(twitch.router, prefix="/twitch", tags=["Twitch"])
router.include_router(github.router, prefix="/github", tags=["GitHub"])

tags_metadata = [
    {
        "name": "Discord",
        "description": "The **Discord** logic is implemented here.",
    }, {
        "name": "Google",
        "description": "The **Google** logic is implemented here.",
    }, {
        "name": "Twitch",
        "description": "The **Twitch** logic is implemented here.",
    }, {
        "name": "GitHub",
        "description": "The **GitHub** logic is implemented here.",
    }
]
