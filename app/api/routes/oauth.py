from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter
from fastapi.exceptions import HTTPException
from fastapi.params import Depends
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.core.db import get_db
from app.core.oauth import oauth, oauth_clients_names
from app.core.config import logger
from app.core.object.oauth import create_oauth_token
from app.core.object.user import get_user_by_email
from app.core.utils import pprint
from app.templates.schemas.oauth import OAuthTokenBase

router = APIRouter()


@router.get('/{provider}')
async def oauth_login(provider: str,  request: Request):
    if provider not in oauth_clients_names:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    provider_client = oauth.create_client(provider)
    return await provider_client.authorize_redirect(request, request.url_for("oauth_callback", provider=provider))


@router.get("/{provider}/callback")
async def oauth_callback(provider: str, request: Request, db: Session = Depends(get_db)):
    try:
        if provider not in oauth_clients_names:
            raise HTTPException(status_code=404, detail="Unsupported provider")
        provider_client = oauth.create_client(provider)
        # Retrieve token and user info from the provider
        try:
            token = await provider_client.authorize_access_token(request)
        except OAuthError as error:
            raise HTTPException(status_code=401, detail=str(error)) from error
        match provider:
            case "microsoft" | "twitter" | "reddit" | "discord":
                raise HTTPException(
                    status_code=501, detail="Not implemented yet")
            case "github":
                user_info = await provider_client.userinfo(token=token)
                emails = await provider_client.get("https://api.github.com/user/emails", token=token)
                emails.raise_for_status()
                user_info["emails"] = emails.json()
            case _:
                user_info = await provider_client.userinfo(token=token)
        if not user_info:
            raise HTTPException(
                status_code=400, detail="Unable to fetch user information")
        pprint(user_info, logging=True)

        # Find or create a user
        db_user = None
        match provider:
            case "twitch":
                if not user_info["email_verified"]:
                    raise HTTPException(
                        status_code=401, detail="You need to verify your email associated with your Twitch account.")
                try:
                    db_user = get_user_by_email(db, user_info["email"])
                except HTTPException as e:
                    if e.status_code == 404:
                        # TODO: Create a new user
                        ...
                    else:
                        raise e
            case "google":
                if not user_info["email_verified"]:
                    raise HTTPException(
                        status_code=401, detail="You need to verify your email associated with your Google account.")
                try:
                    db_user = get_user_by_email(db, user_info["email"])
                except HTTPException as e:
                    if e.status_code == 404:
                        # TODO: Create a new user
                        ...
                    else:
                        raise e
            case "github":
                emails = [
                    email for email in user_info["emails"]
                    if email["verified"] and email["email"].split("@")[-1] != "users.noreply.github.com"
                ]
                primary_emails = [
                    email for email in emails if email["primary"]]
                other_emails = [
                    email for email in emails if not email["primary"]]

                for email_list in (primary_emails, other_emails):
                    for email in email_list:
                        try:
                            db_user = get_user_by_email(db, email["email"])
                            if db_user:
                                break
                        except HTTPException as e:
                            if e.status_code != 404:
                                raise e

                if not db_user:
                    email = (primary_emails + other_emails)[0]["email"]
                    # TODO: Create a new user
                    ...
            case _:
                raise HTTPException(
                    status_code=501, detail="Not implemented yet")
        print(db_user)
        if not db_user:
            # TODO: Raise an error
            ...
        # TODO: Link the OAuth account
        # request.session.update({"user_uuid": db_user.uuid2})
        # oauth_account = db.query(OAuthAccount).filter_by(
        #     provider=provider, provider_user_id=provider_user_id).first()
        # if oauth_account:
        #     user = oauth_account.user
        # else:
        #     user = db.query(User).filter_by(email=user_info["email"]).first()
        #     if not user:
        #         # Create a new user if one does not exist
        #         user = User(
        #             username=user_info["name"], email=user_info["email"], hashed_password="")
        #         db.add(user)
        #         db.commit()

        #     # Link the OAuth account
        #     oauth_account = OAuthAccount(
        #         provider=provider, provider_user_id=provider_user_id, user_id=user.id)
        #     db.add(oauth_account)
        #     db.commit()

        # # Generate JWT token for the user
        # access_token = create_access_token(data={"user_id": user.id})
        # response = RedirectResponse(url="/success")
        # response.set_cookie(key="Authorization", value=f"Bearer {
        #                     access_token}", httponly=True)

        # request.session.update({"user_uuid": "user_uuid"})
        oauth_version = type(provider_client).__name__.replace(
            "StarletteOAuth", "").replace("App", "")
        print("OAuth:", oauth_version)
        # if oauth_version == "1":
        #     new_token = OAuthTokenBase(
        #         oauth_version=oauth_version,
        #         name=provider,
        #         oauth_token=token["token"],
        #         oauth_token_secret=token["token_secret"],
        #         user_uuid="user_uuid", # TODO: once user is created/fetched
        #     )
        # else:
        #     new_token = OAuthTokenBase(
        #         oauth_version=oauth_version,
        #         name=provider,
        #         token_type=token["token_type"],
        #         access_token=token["access_token"],
        #         refresh_token=token["refresh_token"],
        #         expires_at=token["expires_at"],
        #         user_uuid="user_uuid", # TODO: once user is created/fetched
        #     )
        # create_oauth_token(db, new_token)
        # return login token
        auth_token = {"token_type": "Bearer", "access_token": "access_token"}
        html = f"""
        <html>
            <body>
                <script>
                    localStorage.setItem("auth_token", `{auth_token["token_type"]} {auth_token["access_token"]}`);
                    window.location.href = "/";
                </script>
                <!-- DEBUG -->
                <div>{user_info}</div>
            </body>
        </html>
        """
        return HTMLResponse(html)
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))
