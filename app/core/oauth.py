"""
This module provides OAuth integration using Authlib with Starlette.

It handles OAuth client setup and token management, including fetching and updating tokens.
"""

from io import BytesIO
import json
import os
import time
from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client import StarletteOAuth1App as OAuth1App
from authlib.integrations.starlette_client import StarletteOAuth2App as OAuth2App
from fastapi import HTTPException, UploadFile
import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings, logger
from app.core.security import TokenData, create_access_token
from app.core.utils import app_path
from app.core.email import send_validation_email
from app.db_objects.db_models import User as User_DB
from app.db_objects.file import create_file, link_file_user
from app.db_objects.oauth import (fetch_token, update_token)
from app.providers.twitch import get_acc_info as get_twitch_info
from app.providers.google import get_acc_info as get_google_info
from app.providers.discord import get_acc_info as get_discord_info
from app.providers.github import get_acc_info as get_github_info
from app.templates.schemas.file import FileCreate


oauth = OAuth(
    fetch_token=fetch_token,
    update_token=update_token
)

if settings.API_CLIENT_ID_GOOGLE and settings.API_CLIENT_SECRET_GOOGLE:
    oauth.register(
        'google',
        client_id=settings.API_CLIENT_ID_GOOGLE,
        client_secret=settings.API_CLIENT_SECRET_GOOGLE,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        access_token_params=None,
        authorize_params={'access_type': 'offline'},
        client_kwargs={'scope': 'openid profile email',
                       'code_challenge_method': 'S256'}
    )

if settings.API_CLIENT_ID_GITHUB and settings.API_CLIENT_SECRET_GITHUB:
    oauth.register(
        'github',
        client_id=settings.API_CLIENT_ID_GITHUB,
        client_secret=settings.API_CLIENT_SECRET_GITHUB,
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        server_metadata_url='https://token.actions.githubusercontent.com/.well-known/openid-configuration',
        userinfo_endpoint='https://api.github.com/user',
        client_kwargs={'scope': 'openid user:email read:user',
                       'code_challenge_method': 'S256'},
    )

if settings.API_CLIENT_ID_TWITCH and settings.API_CLIENT_SECRET_TWITCH:
    TWITCH_CLAIMS = str({
        "id_token": {
            "email": None,
            "email_verified": None,
            "preferred_username": None,
        },
        "userinfo": {
            "email": None,
            "email_verified": None,
            "picture": None,
            "preferred_username": None,
            "updated_at": None,
        },
    }).replace('None', 'null').replace("'", '"')
    oauth.register(
        'twitch',
        client_id=settings.API_CLIENT_ID_TWITCH,
        client_secret=settings.API_CLIENT_SECRET_TWITCH,
        server_metadata_url='https://id.twitch.tv/oauth2/.well-known/openid-configuration',
        authorize_params={'claims': TWITCH_CLAIMS},
        access_token_params={'client_id': settings.API_CLIENT_ID_TWITCH,
                             'client_secret': settings.API_CLIENT_SECRET_TWITCH},
        client_kwargs={'scope': 'openid user:read:email',
                       'code_challenge_method': 'S256'},
    )

if settings.API_CLIENT_ID_DISCORD and settings.API_CLIENT_SECRET_DISCORD:
    oauth.register(
        'discord',
        client_id=settings.API_CLIENT_ID_DISCORD,
        client_secret=settings.API_CLIENT_SECRET_DISCORD,
        access_token_url='https://discord.com/api/oauth2/token',
        access_token_params=None,
        authorize_url='https://discord.com/oauth2/authorize',
        authorize_params=None,
        api_base_url='https://discord.com/api',
        userinfo_endpoint='https://discord.com/api/users/@me',
        client_kwargs={'scope': 'identify email',
                       'code_challenge_method': 'S256'},
    )

oauth_clients_names = list(oauth._clients)  # pylint: disable=protected-access


async def get_user_info(provider_client: OAuth1App | OAuth2App, token) -> dict:
    """
    Get user information from OAuth provider.

    :param OAuth1App | OAuth2App provider_client: The OAuth client to use.
    :param dict token: The OAuth token to use.
    :return dict: The user information.
    :raises HTTPException: If the user information cannot be fetched.
    """
    match provider_client.name:
        case "github":
            user_info = await provider_client.userinfo(token=token)
            emails = await provider_client.get("https://api.github.com/user/emails", token=token)
            emails.raise_for_status()
            user_info["emails"] = emails.json()
        case "twitter":
            # url = "https://api.twitter.com/2/users/me"
            # url += "?user.fields=id,name,profile_image_url,username"
            # user_info = await provider_client.get(url, token=token)
            # user_info.raise_for_status()
            # user_info = user_info.json()
            raise HTTPException(
                status_code=400,
                detail="Twitter is not supported yet due to lack of way to get user email."
            )
        case _:
            user_info = await provider_client.userinfo(token=token)
    if not user_info:
        raise HTTPException(
            status_code=400, detail="Unable to fetch user information")
    logger.debug(f"\n{json.dumps(user_info, indent=4)}")
    return user_info


def get_external_account_info(provider: str, user_info: dict) -> dict:
    """
    Extract the relevant information from the user info provided by the OAuth provider.

    :param str provider: The name of the OAuth provider.
    :param dict user_info: The user information returned by the OAuth provider.
    :return dict: A dictionary containing the following information:
        - provider: The name of the OAuth provider.
        - id: The user ID.
        - username: The username.
        - display_name: The display name.
        - emails: A list of emails associated with the user.
        - picture_url: The URL of the user's profile picture.

    :raises HTTPException: If the user information does not contain the necessary information.
    """
    data = {"provider": provider}
    match provider:
        case "twitch":
            data = get_twitch_info(user_info)
            if not user_info["email_verified"]:
                raise HTTPException(
                    status_code=401,
                    detail="You need to verify your email associated with your Google account."
                )

        case "google":
            data = get_google_info(user_info)
            if not user_info["email_verified"]:
                raise HTTPException(
                    status_code=401,
                    detail="You need to verify your email associated with your Google account."
                )

        case "discord":
            data = get_discord_info(user_info)
            if not user_info["verified"]:
                raise HTTPException(
                    status_code=401,
                    detail="You need to verify your Discord account. (Email)"
                )

        case "github":
            data = get_github_info(user_info)
            if not data["emails"]:
                raise HTTPException(
                    status_code=401,
                    detail="You need to verify at least one email associated with your GitHub account."
                )

        case _:
            raise HTTPException(
                status_code=400,
                detail="Unsupported provider"
            )
    return data


def create_user_from_oauth(
    db: Session,
    provider,
    new_user: User_DB
):
    """
    Create a new user from OAuth information.

    If the username is already taken, append a timestamp to the username
    and retry the creation process. Upon successful creation, send an email
    verification.

    :param Session db: The current database session.
    :param str provider: The name of the OAuth provider.
    :param User_DB new_user: The user object to create.
    :return User_DB: The newly created user object.
    :raises IntegrityError: If a database integrity error occurs other than a username conflict.
    """
    # Create user
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        os.makedirs(app_path(os.path.join(
            "data", "users", new_user.uuid)), exist_ok=True)
    except IntegrityError as e:
        # Check if the username is already taken, if so add numbers to the username and try again
        if str(e.orig).startswith('UNIQUE') and str(e.orig).endswith('users.username'):
            added_str = str(int(time.time()))
            new_user.username = new_user.username+added_str
            new_user.display_name = new_user.display_name+added_str
            return create_user_from_oauth(db, provider, new_user)
        raise e
    # Send the email verification
    email_token = create_access_token(
        sub=TokenData(
            purpose="email-verification",
            uuid=new_user.uuid,
            email=new_user.email
        )
    )
    send_validation_email(new_user.email, email_token)
    return new_user


def set_profile_picture(db: Session, db_user: User_DB, picture_url: str, provider: str):
    """
    Set the profile picture of the user from an OAuth provider.

    This function downloads the profile picture from the provider, creates a new file
    in the database, links it to the user, and updates the user's profile picture.

    :param Session db: The current database session.
    :param User_DB db_user: The user object to update.
    :param str picture_url: The URL of the profile picture.
    :param str provider: The name of the OAuth provider.
    :raises HTTPException: If the file could not be downloaded or created.
    """
    # pylint: disable=C0415
    from app.db_objects.user import update_user
    from app.templates.schemas.user import UserHistory, UserUpdate

    response = httpx.get(picture_url, timeout=5)
    file = UploadFile(
        file=BytesIO(response.content),
        filename=picture_url.split("/")[-1],
    )
    match provider:
        case "google":
            file.filename = f"pfp_{db_user.uuid}.png"
        case _:
            file.filename = f"pfp_{db_user.uuid}.{
                file.filename.split('.')[-1].lower()}"
    new_file = FileCreate(
        description=f"Profile picture for {
            db_user.username} from {provider}",
        file_name=file.filename,
        created_by_uuid=db_user.uuid
    )
    # pylint: disable=R0801
    file_db = create_file(db, new_file, file)
    link_file_user(db, db_user, file_db)
    update_user(db, db_user, UserUpdate(
        profile_picture_id=file_db.id,
        action=UserHistory(
            action="profile-picture-updated-from-oauth",
            description=f"Profile picture for {
                db_user.username} from {provider} updated",
            by=db_user.uuid
        )
    ))
    # pylint: enable=R0801
