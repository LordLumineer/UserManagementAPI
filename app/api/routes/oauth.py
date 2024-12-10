"""
This module contains the API endpoints for OAuth.
Logging, Signing up, and linking third-party accounts.
"""
from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, Response
from fastapi.exceptions import HTTPException
from fastapi.params import Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request


from app.core.db import get_async_db
from app.core.oauth import (
    get_external_account_info, get_user_info, oauth, oauth_clients_names,
    create_user_from_oauth, set_profile_picture
)
from app.core.security import TokenData, create_access_token
from app.db_objects.oauth import (
    create_oauth_token, delete_oauth_token, get_oauth_token, update_oauth_token
)
from app.db_objects.user import (
    delete_user, get_current_user, get_user, get_user_by_email,
)
from app.db_objects.external_account import delete_external_account, get_external_account, create_external_account
from app.templates.schemas.oauth import OAuthTokenBase
from app.db_objects.db_models import User as User_DB
from app.templates.schemas.external_account import ExternalAccountBase

router = APIRouter()


@router.get('/{provider}', include_in_schema=False)
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


@router.get('/{provider}/link', include_in_schema=False)
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


@router.get("/{provider}/callback", include_in_schema=False)
async def oauth_callback(provider: str, request: Request, db: AsyncSession = Depends(get_async_db), is_link: bool = False):
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
        if await get_external_account(db, provider, user_info["id"]):
            raise HTTPException(
                status_code=409,
                detail=f"This {
                    provider} account is already linked to another user"
            )
        db_user = await get_user(db, request.session.get("user_uuid"))
        # Create Third Party Account
        await create_external_account(
            db,
            external_account=ExternalAccountBase(
                external_account_id=user_info["id"],
                provider=provider,
                user_uuid=db_user.uuid,
                username=user_info["username"],
                display_name=user_info["display_name"],
                email=user_info["emails"][0],
                picture_url=user_info["picture_url"]
            )
        )

    # Connect / Sign Up from External Account
    else:
        external_account = await get_external_account(
            db, provider, user_info["id"], raise_error=False)
        if external_account:
            db_user = await get_user(db, external_account.user_uuid)
        else:
            for email in user_info["emails"]:
                db_user = await get_user_by_email(db, email, raise_error=False)
                if db_user:
                    # Create Third Party Account
                    await create_external_account(
                        db,
                        external_account=ExternalAccountBase(
                            external_account_id=user_info["id"],
                            provider=provider,
                            user_uuid=db_user.uuid,
                            username=user_info["username"],
                            display_name=user_info["display_name"],
                            email=user_info["emails"][0],
                            picture_url=user_info["picture_url"]
                        )
                    )
                    if not db_user.profile_picture_id and user_info["picture_url"]:
                        await set_profile_picture(db, db_user, user_info["picture_url"], provider)
                    break
            if not db_user:
                # Create local user
                db_user = await create_user_from_oauth(
                    db,
                    provider,
                    new_user=User_DB(
                        username=user_info["username"],
                        display_name=user_info["display_name"],
                        email=user_info["emails"][0],
                        hashed_password="ThirdPartyOnlyAcc",
                        is_external_only=True
                    )
                )
                if user_info["picture_url"]:
                    await set_profile_picture(db, db_user, user_info["picture_url"], provider)
                # Create External Account
                await create_external_account(
                    db,
                    external_account=ExternalAccountBase(
                        external_account_id=user_info["id"],
                        provider=provider,
                        user_uuid=db_user.uuid,
                        username=user_info["username"],
                        display_name=user_info["display_name"],
                        email=user_info["emails"][0],
                        picture_url=user_info["picture_url"]
                    )
                )
    # Save Token | Response
    request.session.update({"user_uuid": db_user.uuid})
    oauth_version = type(provider_client).__name__.replace(
        "StarletteOAuth", "").replace("App", "")

    if oauth_version == "1":
        oauth_token = OAuthTokenBase(
            oauth_version=oauth_version,
            provider=provider,
            oauth_token=token["token"],
            oauth_token_secret=token["token_secret"],
            user_uuid=db_user.uuid
        )
    else:
        oauth_token = OAuthTokenBase(
            oauth_version=oauth_version,
            provider=provider,
            token_type=token["token_type"],
            access_token=token["access_token"],
            refresh_token=token["refresh_token"],
            expires_at=token["expires_at"],
            user_uuid=db_user.uuid
        )
    db_token = await get_oauth_token(db, provider, db_user.uuid, raise_error=False)
    if db_token:
        await update_oauth_token(db, db_token, oauth_token)
    else:
        await create_oauth_token(db, oauth_token)

    auth_token = create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=db_user.uuid,
            roles=db_user.roles
        ))
    redirect_uri = "/"
    uri_list = request.session.get("redirect_uri")
    if uri_list:
        redirect_uri = uri_list.pop()
    return HTMLResponse(
        f"""
        <html>
            <body>
                <script>
                    localStorage.setItem("auth_token", `{auth_token.token_type} {auth_token.access_token}`);
                    window.location.replace(`{redirect_uri}`);
                </script>
                <!-- DEBUG -->
                <div>{user_info}</div>
            </body>
        </html>
        """
    )


@router.post("/{provider}/revoke")
@router.post("/{provider}/unlink", include_in_schema=False)
async def oauth_revoke(
    provider: str,
    request: Request,
    current_user: User_DB = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)
):
    """
    Revoke the OAuth token for the given provider and delete the associated
    external account.

    This endpoint is used to delete the OAuth token for a given provider and
    to delete the associated external account. If the user is external only and
    no longer has any external accounts linked, the user is deleted.

    Parameters
    ----------
    provider : str
        The OAuth provider to revoke the token for.
    request : Request
        The request object.
    current_user : User_DB
        The current user object.
    db : Session
        The current database session.

    Raises
    ------
    HTTPException
        If the provider is not supported or if the user doesn't have any
        external accounts linked to their account.

    Returns
    -------
    Response
        A response object with a status code of 200.
    """
    if not current_user.external_accounts:
        raise HTTPException(
            status_code=400,
            detail=f"You don't have any {
                provider} account linked to your account."
        )
    if provider not in oauth_clients_names:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    provider_client = oauth.create_client(provider)
    resp = await provider_client.revoke_token(request)
    resp.raise_for_status()

    # Delete OAuth Token
    await delete_oauth_token(db, await get_oauth_token(db, provider, current_user.uuid))

    # Delete External Account
    external_account = next(
        (account for account in current_user.external_accounts if account.provider == provider), None)
    if not external_account:
        raise HTTPException(
            status_code=400,
            detail=f"You don't have any {
                provider} account linked to your account."
        )
    await delete_external_account(db, await get_external_account(
        db, provider, external_account.external_account_id))

    # Delete User if External Only and no longer linked to any account
    if not current_user.external_accounts and current_user.is_external_only:
        await delete_user(db, current_user)

    return Response(status_code=200)
# ~~~~~ Utility Functions ~~~~~ #
