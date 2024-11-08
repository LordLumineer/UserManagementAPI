"""
This module contains the API endpoints for OAuth.
Logging, Signing up, and linking third-party accounts.

@file: ./app/api/routes/oauth.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from io import BytesIO
import time
from authlib.integrations.starlette_client import OAuthError
from authlib.integrations.starlette_client import StarletteOAuth1App as OAuth1App
from authlib.integrations.starlette_client import StarletteOAuth2App as OAuth2App
from fastapi import APIRouter, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.params import Depends
from fastapi.responses import HTMLResponse
import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.requests import Request


from app.core.db import get_db
from app.core.email import send_validation_email
from app.core.oauth import oauth, oauth_clients_names
from app.core.object.file import create_file
from app.core.object.oauth import create_oauth_token
from app.core.object.user import get_current_user, get_user, get_user_by_email, link_file_to_user, update_user
from app.core.object.external_account import get_external_account, create_external_account
from app.core.security import TokenData, create_access_token
from app.core.utils import pprint
from app.templates.schemas.file import FileCreate
from app.templates.schemas.oauth import OAuthTokenBase
from app.templates.models import User as User_Model
from app.templates.schemas.external_account import ExternalAccountBase
from app.templates.schemas.user import UserUpdate

router = APIRouter()


@router.get('/{provider}')
async def oauth_login(provider: str,  request: Request):
    """
    Redirect user to the OAuth provider login page.

    Parameters
    ----------
    provider : str
        The OAuth provider to use (e.g. "google", "discord", ...).
    request : Request
        The request object.

    Returns
    -------
    Response
        The redirect response to the OAuth provider login page.
    """
    if provider not in oauth_clients_names:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    provider_client = oauth.create_client(provider)
    return await provider_client.authorize_redirect(
        request,
        request.url_for("oauth_callback", provider=provider)
    )


@router.get('/{provider}/link')
async def oauth_link(provider: str, request: Request, current_user: User_Model = Depends(get_current_user),):
    """
    Redirect user to the OAuth provider login page to link a third-party account.

    Parameters
    ----------
    provider : str
        The OAuth provider to use (e.g. "google", "discord", ...).
    request : Request
        The request object.
    current_user : User_Model
        The current user.

    Returns
    -------
    Response
        The redirect response to the OAuth provider login page.
    """
    if provider not in oauth_clients_names:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    provider_client = oauth.create_client(provider)
    request.session.update({"user_uuid": current_user.uuid})
    return await provider_client.authorize_redirect(
        request,
        request.url_for("oauth_callback", provider=provider, is_link=True)
    )


@router.get("/{provider}/callback")
async def oauth_callback(provider: str, request: Request, db: Session = Depends(get_db), is_link: bool = False):
    """
    Handle OAuth callback from a provider.

    Parameters
    ----------
    provider : str
        The OAuth provider to use (e.g. "google", "discord", ...).
    request : Request
        The request object.
    db : Session
        The database session.

    Returns
    -------
    Response
        The redirect response to the main page of the app.
    """
    if provider not in oauth_clients_names:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    provider_client = oauth.create_client(provider)
    # Retrieve token and user info from the provider
    try:
        token = await provider_client.authorize_access_token(request)
    except OAuthError as error:
        raise HTTPException(status_code=401, detail=str(error)) from error

    user_info = await get_user_info(provider_client, token)
    pprint(user_info, logging=True)

    # Find or create a user
    db_user = None

    if is_link:
        match provider:
            case "twitch" | "google":
                external_acc_id = user_info["sub"]
            case "github" | "discord":
                external_acc_id = user_info["id"]
            case _:
                raise HTTPException(
                    status_code=501, detail="Not implemented yet")
        if get_user_by_third_party_id(db, external_acc_id):
            raise HTTPException(
                status_code=409,
                detail=f"This {
                    provider} account is already linked to another user"
            )

        db_user = get_user(db, request.session.get("user_uuid"))
        # Create Third Party Account
        create_external_account(
            db,
            external_account=ExternalAccountBase(
                external_acc_id=external_acc_id,
                provider=provider,
                user_uuid=db_user.uuid
            )
        )

    else:
        # Flow:
        #   Check if ExternalAccount exists (acc id)
        #   -> Check if LocalUser exists (email if email verified)
        #   -> Create LocalUser
        match provider:
            case "twitch":
                db_user = get_user_by_third_party_id(db, user_info["sub"])
                if not db_user:
                    if not user_info["email_verified"]:
                        raise HTTPException(
                            status_code=401,
                            detail="You need to verify your email associated with your Twitch account."
                        )
                    db_user = await get_or_create_user(
                        db,
                        provider,
                        external_acc_id=user_info["sub"],
                        new_user=User_Model(
                            username=user_info["preferred_username"].lower().replace(
                                " ", "_"),
                            display_name=user_info["preferred_username"],
                            email=user_info["email"],
                            hashed_password="ThirdPartyOnlyAcc",
                            is_third_part_only=True
                        ),
                        picture_url=user_info["picture"]
                    )
            case "google":
                db_user = get_user_by_third_party_id(db, user_info["sub"])
                if not db_user:
                    if not user_info["email_verified"]:
                        raise HTTPException(
                            status_code=401,
                            detail="You need to verify your email associated with your Google account."
                        )
                    db_user = await get_or_create_user(
                        db,
                        provider,
                        external_acc_id=user_info["sub"],
                        new_user=User_Model(
                            username=user_info["name"].lower().replace(
                                " ", "_"),
                            display_name=user_info["name"],
                            email=user_info["email"],
                            hashed_password="ThirdPartyOnlyAcc",
                            is_third_part_only=True
                        ),
                        picture_url=user_info["picture"]
                    )
            case "github":
                db_user = get_user_by_third_party_id(db, user_info["id"])
                if not db_user:
                    emails = [
                        email for email in user_info["emails"]
                        if email["verified"] and email["email"].split("@")[-1] != "users.noreply.github.com"
                    ]
                    if not emails:
                        raise HTTPException(
                            status_code=401,
                            detail="You need to verify at least one email associated with your GitHub account."
                        )
                    primary_emails = [
                        email for email in emails if email["primary"]]
                    other_emails = [
                        email for email in emails if not email["primary"]]
                    for email in (primary_emails + other_emails):
                        db_user = await get_or_create_user(
                            db,
                            provider,
                            external_acc_id=user_info["id"],
                            new_user=User_Model(
                                username=user_info["login"].lower().replace(
                                    " ", "_"),
                                display_name=user_info["login"],
                                email=email,
                                hashed_password="ThirdPartyOnlyAcc",
                                is_third_part_only=True
                            ),
                            picture_url=user_info["avatar_url"] + ".png"
                        )
                        if db_user:
                            break
            case "discord":
                db_user = get_user_by_third_party_id(db, user_info["id"])
                if not db_user:
                    if not user_info["verified"]:
                        raise HTTPException(
                            status_code=401,
                            detail="You need to verify your Discord account. (Email)"
                        )
                    db_user = await get_or_create_user(
                        db,
                        provider,
                        external_acc_id=user_info["id"],
                        new_user=User_Model(
                            username=user_info["username"].lower().replace(
                                " ", "_"),
                            display_name=user_info["username"],
                            email=user_info["email"],
                            hashed_password="ThirdPartyOnlyAcc",
                            is_third_part_only=True
                        ),
                        picture_url=f"https://cdn.discordapp.com/avatars/{
                            user_info['id']}/{user_info['avatar']}.png"
                    )
            case _:
                raise HTTPException(
                    status_code=501, detail="Not implemented yet")

    request.session.update({"user_uuid": db_user.uuid})
    oauth_version = type(provider_client).__name__.replace(
        "StarletteOAuth", "").replace("App", "")
    if oauth_version == "1":
        create_oauth_token(
            db,
            OAuthTokenBase(
                oauth_version=oauth_version,
                name=provider,
                oauth_token=token["token"],
                oauth_token_secret=token["token_secret"],
                user_uuid=db_user.uuid
            )
        )
    else:
        create_oauth_token(
            db,
            OAuthTokenBase(
                oauth_version=oauth_version,
                name=provider,
                token_type=token["token_type"],
                access_token=token["access_token"],
                refresh_token=token["refresh_token"],
                expires_at=token["expires_at"],
                user_uuid=db_user.uuid
            )
        )

    auth_token = create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=db_user.uuid,
            permission=db_user.permission
        ))
    return HTMLResponse(
        f"""
        <html>
            <body>
                <script>
                    localStorage.setItem("auth_token", `{auth_token.token_type} {auth_token.access_token}`);
                    window.location.href = "/";
                </script>
                <!-- DEBUG -->
                <div>{user_info}</div>
            </body>
        </html>
        """
    )


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
            raise HTTPException(
                status_code=400,
                detail="Twitter is not supported yet due to lack of way to get user email."
            )
            # url = "https://api.twitter.com/2/users/me"
            # url += "?user.fields=id,name,profile_image_url,username"
            # user_info = await provider_client.get(url, token=token)
            # user_info.raise_for_status()
            # user_info = user_info.json()
        case _:
            user_info = await provider_client.userinfo(token=token)
    if not user_info:
        raise HTTPException(
            status_code=400, detail="Unable to fetch user information")
    return user_info


def get_user_by_third_party_id(db: Session, third_party_id: str) -> User_Model:
    """
    Get a user by their third-party account ID.

    :param Session db: The current database session.
    :param str third_party_id: The third-party account ID to get the user for.
    :return User_Model: The user model object.
    """
    try:
        external_account = get_external_account(db, third_party_id)
        return get_user(db, external_account.user_uuid)
    except HTTPException as e:
        if e.status_code != 404:
            raise e
    return None


async def get_or_create_user(db: Session, provider, external_acc_id, new_user: User_Model, picture_url) -> User_Model:
    """
    Get a user by their email, or create them if they don't exist.

    If the user exists, return them. If they don't exist, create a new user
    with the provided email and create a new OAuth token for the user with
    the provided provider and account ID.

    :param Session db: The current database session.
    :param str provider: The name of the OAuth provider.
    :param str external_acc_id: The ID of the user's account on the provider.
    :param User_Model new_user: The new user object to create.
    :param str picture_url: The URL of the user's profile picture.
    :return User_Model: The user model object.
    """
    try:
        return get_user_by_email(db, new_user.email)
    except HTTPException as e:
        if e.status_code != 404:
            raise e
        return await create_oauth_account(db, provider, external_acc_id, new_user, picture_url)


async def create_oauth_account(
    db: Session,
    provider,
    external_acc_id,
    new_user: User_Model,
    picture_url=None
):
    """
    Create a new user account with OAuth provider details.

    This function attempts to add a new user to the database using the provided
    user details. If a username conflict occurs, it appends a timestamp to the
    username and display name, then retries the creation. An email verification
    token is generated and sent to the user's email. If a picture URL is provided,
    it downloads the image, creates a file entry, and links it as the user's
    profile picture. Finally, a third-party account is created and linked to
    the user.

    :param Session db: The current database session.
    :param str provider: The name of the OAuth provider.
    :param str external_acc_id: The ID of the user's account on the provider.
    :param User_Model new_user: The new user object to create.
    :param str picture_url: The URL of the user's profile picture.
    :return User_Model: The created user model object.
    :raises HTTPException: If a database integrity error occurs.
    """
    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except IntegrityError as e:
        db.rollback()
        if str(e.orig).startswith('UNIQUE') and str(e.orig).endswith('users.username'):
            added_str = str(int(time.time()))
            new_user.username = new_user.username+added_str
            new_user.display_name = new_user.display_name+added_str
            return await create_oauth_account(db, provider, new_user, picture_url)
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    email_token = create_access_token(
        sub=TokenData(
            purpose="email-verification",
            uuid=new_user.uuid,
            email=new_user.email
        ))
    await send_validation_email(new_user.email, email_token)
    if picture_url:
        response = httpx.get(picture_url, timeout=5)
        file = UploadFile(
            file=BytesIO(response.content),
            filename=picture_url.split("/")[-1],
        )

        match provider:
            case "google":
                file.filename = f"pfp_{new_user.uuid}.png"
            case _:
                file.filename = f"pfp_{new_user.uuid}.{
                    file.filename.split('.')[-1].lower()}"
        new_file = FileCreate(
            description=f"Profile picture for {
                new_user.username} from {provider}",
            file_name=file.filename,
            created_by=new_user.uuid
        )
        file = UploadFile(BytesIO(response.content), )
        file_db = await create_file(db, new_file, file)
        link_file_to_user(db, new_user.uuid, file_db.id)
        await update_user(db, new_user.uuid, UserUpdate(profile_picture_id=file_db.id))

    # Create Third Party Account
    create_external_account(
        db,
        external_account=ExternalAccountBase(
            external_acc_id=external_acc_id,
            provider=provider,
            user_uuid=new_user.uuid
        )
    )
    return new_user
