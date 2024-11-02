from typing import Literal
from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter
from starlette.requests import Request

from app.core.oauth import oauth
from app.core.config import settings

router = APIRouter()

# Login with provider
@router.get('/{provider}')
async def auth(provider: str,  request):
    print(oauth)
    print(provider in oauth)
    return (provider, request, oauth)