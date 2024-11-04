from fastapi import HTTPException
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.templates.models import users_oauth_links
from app.templates.models import OAuthToken as OAuthTokenModel
from app.templates.schemas.oauth import OAuthTokenBase


def get_oauth_token(db: Session, name: str, user_uuid: str) -> OAuthTokenModel:
    db_token = db.query(OAuthTokenModel).filter(
        OAuthTokenModel.name == name,
        OAuthTokenModel.user_uuid == user_uuid
    ).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")
    return db_token


def create_oauth_token(db: Session, new_token: OAuthTokenBase) -> OAuthTokenModel:
    db_token = OAuthTokenModel(**new_token.model_dump())
    try:
        db.add(db_token)
        db.commit()
        db.refresh(db_token)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    link_user_to_token(db, db_token.id, db_token.user_uuid)
    return db_token


def update_oauth_token(db: Session, new_token: OAuthTokenBase, name: str, user_uuid: str, **kwargs) -> OAuthTokenModel:
    db_token = get_oauth_token(db, name, user_uuid)
    for field, value in new_token.items():
        setattr(db_token, field, value)
    try:
        db.add(db_token)
        db.commit()
        db.refresh(db_token)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    return db_token


def delete_oauth_token(db: Session, name: str, user_uuid: str) -> bool:
    db_token = get_oauth_token(db, name, user_uuid)
    db.delete(db_token)
    db.commit()
    return True


def link_user_to_token(db: Session, token_id: int, user_uuid: str) -> None:
    db.execute(
        insert(users_oauth_links).values(
            user_uuid=user_uuid, oauth_token_id=token_id)
    )
    db.commit()
    return token_id


# ----- authlib OAuth client functions ----- #

def fetch_token(name, request):
    """
    This is the authlib OAuth client auto fetch token.

    For more information, please refer to the documentation of
    `authlib.integrations.starlette_client.OAuth.register` and
    `authlib.integrations.starlette_client.OAuth.fetch_token`.

    :param name: The name of the OAuth client
    :param request: The request object
    :return: The OAuth token
    """
    db = next(get_db())
    try:
        token = db.query(OAuthTokenModel).filter(
            OAuthTokenModel.name == name,
            OAuthTokenModel.user_uuid == request.session.get("user_uuid")
        ).first()
        if not token:
            return
        token = OAuthTokenBase(**token)
    finally:
        db.close()
    return token.to_token()


def update_token(name, token, refresh_token=None, access_token=None):
    """
    This is the authlib OAuth client autoupdate.

    For more information, please refer to the documentation of
    `authlib.integrations.starlette_client.OAuth.register` and
    `authlib.integrations.starlette_client.OAuth.update_token`.

    :param name: The name of the OAuth client
    :param token: The OAuth token returned from the provider
    :param refresh_token: The refresh token of the OAuth client
    :param access_token: The access token of the OAuth client
    :return: Nothing
    """
    db = next(get_db())
    try:
        if refresh_token:
            item = db.query(OAuthTokenModel).filter(
                OAuthTokenModel.name == name,
                OAuthTokenModel.refresh_token == refresh_token
            ).first()
        elif access_token:
            item = db.query(OAuthTokenModel).filter(
                OAuthTokenModel.name == name,
                OAuthTokenModel.access_token == access_token
            ).first()
        else:
            return

        # update old token
        try:
            item.access_token = token['access_token']
            item.refresh_token = token.get('refresh_token')
            item.expires_at = token['expires_at']
            db.add(item)
            db.commit()
            db.refresh(item)
        except IntegrityError as e:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(e.orig)) from e
    finally:
        db.close()
