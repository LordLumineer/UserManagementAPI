from io import BytesIO
import time
from authlib.integrations.starlette_client import OAuthError
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
from app.core.object.user import get_user_by_email, link_file_to_user, update_user
from app.core.security import TokenData, create_access_token
from app.core.utils import pprint
from app.templates.schemas.file import FileCreate
from app.templates.schemas.oauth import OAuthTokenBase
from app.templates.models import User as User_Model
from app.templates.schemas.user import UserUpdate

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
            case "microsoft" | "twitter" | "reddit":
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
                        db_user = await create_oauth_account(
                            db,
                            provider,
                            username=user_info["preferred_username"].lower().replace(
                                " ", "_"),
                            display_name=user_info["preferred_username"],
                            email=user_info["email"],
                            picture_url=user_info["picture"]
                        )
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
                        db_user = await create_oauth_account(
                            db,
                            provider,
                            username=user_info["name"].lower().replace(
                                " ", "_"),
                            display_name=user_info["name"],
                            email=user_info["email"],
                            picture_url=user_info["picture"]
                        )
                    else:
                        raise e
            case "github":
                emails = [
                    email for email in user_info["emails"]
                    if email["verified"] and email["email"].split("@")[-1] != "users.noreply.github.com"
                ]
                if not emails:
                    raise HTTPException(
                        status_code=401, detail="You need to verify at least one email associated with your GitHub account.")
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
                    db_user = await create_oauth_account(
                        db,
                        provider,
                        username=user_info["login"].lower().replace(" ", "_"),
                        display_name=user_info["login"],
                        email=email,
                        picture_url=user_info["avatar_url"] + ".png"
                    )
            case "discord":
                if not user_info["verified"]:
                    raise HTTPException(
                        status_code=401, detail="You need to verify your Discord account. (Email)")
                try:
                    db_user = get_user_by_email(db, user_info["email"])
                except HTTPException as e:
                    if e.status_code == 404:
                        db_user = await create_oauth_account(
                            db,
                            provider,
                            username=user_info["username"].lower().replace(
                                " ", "_"),
                            display_name=user_info["username"],
                            email=user_info["email"],
                            picture_url=f"https://cdn.discordapp.com/avatars/{
                                user_info['id']}/{user_info['avatar']}.png"
                        )
                    else:
                        raise e
            case _:
                raise HTTPException(
                    status_code=501, detail="Not implemented yet")
        if not db_user:
            raise HTTPException(status_code=400, detail="Unable to create or find user")

        request.session.update({"user_uuid": db_user.uuid})
        oauth_version = type(provider_client).__name__.replace(
            "StarletteOAuth", "").replace("App", "")
        if oauth_version == "1":
            new_token = OAuthTokenBase(
                oauth_version=oauth_version,
                name=provider,
                oauth_token=token["token"],
                oauth_token_secret=token["token_secret"],
                user_uuid=db_user.uuid
            )
        else:
            new_token = OAuthTokenBase(
                oauth_version=oauth_version,
                name=provider,
                token_type=token["token_type"],
                access_token=token["access_token"],
                refresh_token=token["refresh_token"],
                expires_at=token["expires_at"],
                user_uuid=db_user.uuid
            )
        create_oauth_token(db, new_token)
        auth_token = create_access_token(
            sub=TokenData(
                purpose="login",
                uuid=db_user.uuid,
                permission=db_user.permission
            ))
        html = f"""
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
        return HTMLResponse(html)
    except Exception as e:
        print(e)
        pprint(token, True)
        raise HTTPException(status_code=500, detail=str(e))


async def create_oauth_account(db: Session, provider, username, display_name, email, picture_url=None):
    try:
        db_user = User_Model(
            username=username,
            display_name=display_name,
            email=email,
            hashed_password="ThirdPartyOnlyAcc",
            is_third_part_only=True
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError as e:
        db.rollback()
        if str(e.orig).startswith('UNIQUE') and str(e.orig).endswith('users.username'):
            added_str = str(int(time.time()))
            return await create_oauth_account(db, provider, username+added_str, display_name+added_str, email, picture_url)
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    email_token = create_access_token(
        sub=TokenData(
            purpose="email-verification",
            uuid=db_user.uuid,
            email=db_user.email
        ))
    await send_validation_email(db_user.email, email_token)
    if picture_url:
        response = httpx.get(picture_url, timeout=5)
        file = UploadFile(
            file=BytesIO(response.content),
            filename=picture_url.split("/")[-1],
        )

        match provider:
            case "google":
                file.filename = f"pfp_{db_user.uuid}.png"
            case _:
                file.filename = f"pfp_{db_user.uuid}.{file.filename.split('.')[-1].lower()}"
        new_file = FileCreate(
            description=f"Profile picture for {
                db_user.username} from {provider}",
            file_name=file.filename,
            created_by=db_user.uuid
        )
        file = UploadFile(BytesIO(response.content), )
        file_db = await create_file(db, new_file, file)
        link_file_to_user(db, db_user.uuid, file_db.id)
        await update_user(db, db_user.uuid, UserUpdate(profile_picture_id=file_db.id))

    return db_user
