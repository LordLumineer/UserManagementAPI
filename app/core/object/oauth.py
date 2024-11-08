"""
This module contains functions for managing OAuth tokens in the database,
including creating, updating, deleting, and linking tokens to users. It also
provides functions for integrating with authlib's OAuth client for automatic
token fetching and updating.

@file: ./app/core/object/oauth.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from fastapi.exceptions import HTTPException
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import logger
from app.core.db import get_db
from app.templates.models import users_oauth_links
from app.templates.models import OAuthToken as OAuthTokenModel
from app.templates.schemas.oauth import OAuthTokenBase


def get_oauth_token(db: Session, name: str, user_uuid: str) -> OAuthTokenModel:
    """Print a JSON representation of an object to the console or log it to the debug level.

    :param Session db: The database session.
    :param str name: The name of the OAuth token.
    :param str user_uuid: The user UUID of the OAuth token.
    :return OAuthTokenModel: The OAuth token model object.
    """
    db_token = db.query(OAuthTokenModel).filter(
        OAuthTokenModel.name == name,
        OAuthTokenModel.user_uuid == user_uuid
    ).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")
    return db_token


def create_oauth_token(db: Session, new_token: OAuthTokenBase) -> OAuthTokenModel:
    """
    Create a new OAuth token in the database and link it to a user.

    This function creates a new OAuth token based on the provided token details
    and inserts it into the database. It also establishes a link between the 
    user and the token. If an integrity error occurs during the insertion,
    an HTTPException is raised.

    :param Session db: The database session.
    :param OAuthTokenBase new_token: The token details to create.
    :return OAuthTokenModel: The created OAuth token model object.
    """
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


def update_oauth_token(db: Session, new_token: OAuthTokenBase, name: str, user_uuid: str) -> OAuthTokenModel:
    """
    Update an existing OAuth token in the database.

    This function updates the fields of an existing OAuth token with the
    provided token details and commits the changes to the database. If an
    integrity error occurs during the update, an HTTPException is raised.

    :param Session db: The database session.
    :param OAuthTokenBase new_token: The new token details to update.
    :param str name: The name of the OAuth token.
    :param str user_uuid: The user UUID of the OAuth token.
    :param kwargs: Additional keyword arguments.
    :return OAuthTokenModel: The updated OAuth token model object.
    :raises HTTPException: If there is an integrity error during the update.
    """
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
    """
    Delete an existing OAuth token from the database.

    This function deletes an existing OAuth token by finding it with the
    specified name and user UUID, and then removing it from the database.
    If the deletion is successful, it returns True.

    :param Session db: The database session.
    :param str name: The name of the OAuth token.
    :param str user_uuid: The user UUID of the OAuth token.
    :return bool: Whether the deletion was successful.
    """
    db_token = get_oauth_token(db, name, user_uuid)
    db.delete(db_token)
    db.commit()
    return True


def link_user_to_token(db: Session, token_id: int, user_uuid: str) -> int:
    """
    Link a user to an OAuth token.

    This function inserts a new record in the `users_oauth_links` table
    to establish a link between the user and the OAuth token.

    :param Session db: The database session.
    :param int token_id: The ID of the OAuth token.
    :param str user_uuid: The UUID of the user.
    :return None: There is no return value.
    """
    db.execute(
        insert(users_oauth_links).values(
            user_uuid=user_uuid, oauth_token_id=token_id)
    )
    db.commit()
    return token_id


# ----- authlib OAuth client functions ----- #

def fetch_token(name, request) -> dict:
    """
    This is the authlib OAuth client auto fetch token.

    For more information, please refer to the documentation of
    `authlib.integrations.starlette_client.OAuth.register` and
    `authlib.integrations.starlette_client.OAuth.fetch_token`.

    :param name: The name of the OAuth client
    :param request: The request object
    :return dict: The OAuth token
    """
    db = next(get_db())
    try:
        token = db.query(OAuthTokenModel).filter(
            OAuthTokenModel.name == name,
            OAuthTokenModel.user_uuid == request.session.get("user_uuid")
        ).first()
        if not token:
            return None
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
    logger.debug("Updating token: %s", name)
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
