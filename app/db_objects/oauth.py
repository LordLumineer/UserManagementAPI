"""This module contains functions for CRUD operations on OAuth tokens from external services."""
from fastapi.exceptions import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import logger
from app.core.db import get_db
from app.db_objects.db_models import OAuthToken as OAuthToken_DB
from app.templates.schemas.oauth import OAuthTokenBase


# ~~~~~ CRUD ~~~~~ #


# ------- Create ------- #


def create_oauth_token(db: Session, token: OAuthTokenBase) -> OAuthToken_DB:
    """
    Create a new OAuth token and link it to a user.

    This function adds a new OAuth token to the database using the details
    provided in the `token` parameter. It also creates an association
    between the user and the OAuth token in the linking table.

    :param Session db: The current database session.
    :param OAuthTokenBase token: The token details to be added.
    :return OAuthToken_DB: The created OAuth token model object.
    :raises HTTPException: If a database integrity error occurs.
    """
    try:
        db_token = OAuthToken_DB(**token.model_dump())
        db.add(db_token)
        db.commit()
        db.refresh(db_token)
    except IntegrityError as e:
        db.rollback()
        raise e
    return db_token


# ------- Read ------- #


def get_oauth_token(db: Session, provider: str, user_uuid: str, raise_error: bool = True) -> OAuthToken_DB:
    """
    Get an OAuth token by provider name for a user.

    :param Session db: The current database session.
    :param str provider: The name of the provider of the OAuth token to retrieve.
    :param str user_uuid: The UUID of the user owning the OAuth token.
    :param bool raise_error: Whether to raise an error if the token is not found (default: True).
    :return OAuthToken_DB: The retrieved OAuth token model object.
    :raises HTTPException: If the token is not found and `raise_error` is `True`.
    """
    db_token = db.query(OAuthToken_DB).filter(
        OAuthToken_DB.provider == provider,
        OAuthToken_DB.user_uuid == user_uuid
    ).first()
    if not db_token and raise_error:
        raise HTTPException(status_code=404, detail="Token not found")
    return db_token


# ------- Update ------- #


def update_oauth_token(db: Session, db_token: OAuthToken_DB, token: OAuthTokenBase) -> OAuthToken_DB:
    """
    Update an existing OAuth token in the database.

    This function updates the fields of an existing OAuth token with the
    values provided in the `token` parameter. It commits the changes to
    the database and refreshes the token object to reflect the updated state.

    :param Session db: The current database session.
    :param OAuthToken_DB db_token: The existing OAuth token model object to update.
    :param OAuthTokenBase token: The new token details to update the existing token with.
    :return OAuthToken_DB: The updated OAuth token model object.
    :raises HTTPException: If a database integrity error occurs.
    """
    token_data = token.model_dump(exclude_unset=True, exclude_none=True)
    for field, value in token_data.items():
        setattr(db_token, field, value)
    try:
        db.add(db_token)
        db.commit()
        db.refresh(db_token)
    except IntegrityError as e:
        db.rollback()
        raise e
    return db_token


# ------- Delete ------- #


def delete_oauth_token(db: Session, oauth_token: OAuthToken_DB) -> bool:
    """
    Delete an OAuth token from the database.

    This function removes an OAuth token and its associated user link
    from the database. It commits the changes and returns a boolean
    indicating success.

    :param Session db: The current database session.
    :param OAuthToken_DB oauth_token: The OAuth token model object to delete.
    :return bool: True if the operation is successful.
    """
    db.delete(oauth_token)
    db.commit()
    return True


# ----- authlib OAuth client functions ----- #


def fetch_token(provider, request) -> dict:
    """
    Fetch an OAuth token from the database.

    This function is used by authlib as the fetch_token function
    for the OAuth client.

    :param provider: The name of the provider of the OAuth client
    :param request: The request object
    :return: The OAuth token as a dictionary
    """
    db = next(get_db())
    try:
        item = db.query(OAuthToken_DB).filter(
            OAuthToken_DB.provider == provider,
            OAuthToken_DB.user_uuid == request.session.get("user_uuid")
        ).first()
        if not item:
            return None
        token = OAuthTokenBase(**item)
    finally:
        db.close()
    return token.to_token()


def update_token(provider, token, refresh_token=None, access_token=None):
    """
    Update an OAuth token in the database.

    This function is used by authlib as the update_token function
    for the OAuth client.

    :param provider: The provider name of the OAuth client
    :param token: The new OAuth token
    :param refresh_token: The refresh token to update
    :param access_token: The access token to update
    :return: None
    """
    logger.debug("Updating token: %s", provider)
    db = next(get_db())
    try:
        if refresh_token:
            item = db.query(OAuthToken_DB).filter(
                OAuthToken_DB.provider == provider,
                OAuthToken_DB.refresh_token == refresh_token
            ).first()
        elif access_token:
            item = db.query(OAuthToken_DB).filter(
                OAuthToken_DB.provider == provider,
                OAuthToken_DB.access_token == access_token
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
            raise e
    finally:
        db.close()
