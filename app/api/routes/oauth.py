"""
This module contains the API endpoints for OAuth.
Logging, Signing up, and linking third-party accounts.
"""
from io import BytesIO
import os
from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, UploadFile
from fastapi.exceptions import HTTPException
from fastapi.params import Depends
from fastapi.responses import HTMLResponse
import httpx
from sqlalchemy.orm import Session
from starlette.requests import Request


from app.core.db import get_db
from app.core.oauth import (
    get_external_account_info, get_user_info, oauth, oauth_clients_names,
    create_user_from_oauth
)
from app.core.security import TokenData, create_access_token
from app.db_objects.file import create_file
from app.db_objects.oauth import (
    create_oauth_token, get_oauth_token, update_oauth_token
)
from app.db_objects.user import (
    get_current_user, get_user, get_user_by_email,
    update_user
)
from app.db_objects.external_account import get_external_account, create_external_account
from app.db_objects.file import link_file_user
from app.templates.schemas.file import FileCreate
from app.templates.schemas.oauth import OAuthTokenBase
from app.db_objects.db_models import User as User_DB
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
async def oauth_link(provider: str, request: Request, current_user: User_DB = Depends(get_current_user),):
    """
    Redirect user to the OAuth provider login page to link a third-party account.

    Parameters
    ----------
    provider : str
        The OAuth provider to use (e.g. "google", "discord", ...).
    request : Request
        The request object.
    current_user : User_DB
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
    user_info = get_external_account_info(provider, user_info)

    # GET or CREATE User / External Account

    db_user = None

    # Link External Account to Logged In User
    if is_link:
        if get_external_account(db, user_info["id"]):
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
                external_account_id=user_info["id"],
                provider=provider,
                user_uuid=db_user.uuid
            )
        )

    # Connect / Sign Up from External Account
    else:
        external_account = get_external_account(db, user_info["id"], raise_error=False)
        if external_account:
            db_user = get_user(db, external_account.user_uuid)
        else:
            for email in user_info["emails"]:
                db_user = get_user_by_email(db, email, raise_error=False)
                if db_user:
                    break
            if not db_user:
                # Create local user
                db_user = await create_user_from_oauth(
                    db,
                    provider,
                    new_user=User_DB(
                        username=user_info["username"],
                        display_name=user_info["display_name"],
                        email=user_info["email"],
                        hashed_password="ThirdPartyOnlyAcc",
                        is_external_only=True
                    )
                )
                if user_info["picture_url"]:
                    response = httpx.get(user_info["picture_url"], timeout=5)
                    file = UploadFile(
                        file=BytesIO(response.content),
                        filename=user_info["picture_url"].split("/")[-1],
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
                        file_name=os.path.join(
                            "users", db_user.uuid, file.filename),
                        created_by=db_user.uuid
                    )
                    file_db = await create_file(db, new_file, file)
                    link_file_user(db, db_user, file_db)
                    await update_user(db, db_user, UserUpdate(profile_picture_id=file_db.id))
                # Create External Account
                create_external_account(
                    db,
                    external_account=ExternalAccountBase(
                        external_account_id=user_info["id"],
                        provider=provider,
                        user_uuid=db_user.uuid
                    )
                )

    # Save Token | Response
    request.session.update({"user_uuid": db_user.uuid})
    oauth_version = type(provider_client).__name__.replace(
        "StarletteOAuth", "").replace("App", "")

    if oauth_version == "1":
        oauth_token = OAuthTokenBase(
            oauth_version=oauth_version,
            name=provider,
            oauth_token=token["token"],
            oauth_token_secret=token["token_secret"],
            user_uuid=db_user.uuid
        )
    else:
        oauth_token = OAuthTokenBase(
            oauth_version=oauth_version,
            name=provider,
            token_type=token["token_type"],
            access_token=token["access_token"],
            refresh_token=token["refresh_token"],
            expires_at=token["expires_at"],
            user_uuid=db_user.uuid
        )
    db_token = get_oauth_token(db, provider, db_user.uuid, raise_error=False)
    if db_token:
        update_oauth_token(db, db_token, oauth_token)
    else:
        create_oauth_token(db, oauth_token)

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


# # TODO: Revoke/Unlink


# @router.post("/{provider}/revoke")
# async def oauth_revoke(
#     provider: str,
#     request: Request,
#     current_user: User_DB = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     if provider not in oauth_clients_names:
#         raise HTTPException(status_code=404, detail="Unsupported provider")
#     provider_client = oauth.create_client(provider)

#     resp = await provider_client.revoke_token(request)
#     resp.raise_for_status()

#     delete_oauth_token(db, get_oauth_token(db, provider, current_user.uuid))

#     external_accounts = current_user.external_accounts
#     external_account = next(
#         (account for account in external_accounts if account.provider == provider), None)

#     if external_account:
#         delete_external_account(db, external_account)
#     if current_user.is_external_only and len(external_accounts) == 1:
#         ...
#         # TODO: Delete account

#     return Response(status_code=200)

# ~~~~~ Utility Functions ~~~~~ #
