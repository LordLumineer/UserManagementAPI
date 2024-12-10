"""This module contains functions for CRUD operations on OAuth tokens from external services."""
from fastapi.exceptions import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import logger
from app.core.db import sessionmanager
from app.db_objects.db_models import OAuthToken as OAuthToken_DB
from app.templates.schemas.oauth import OAuthTokenBase


# ~~~~~ CRUD ~~~~~ #


# ------- Create ------- #


async def create_oauth_token(db: AsyncSession, token: OAuthTokenBase) -> OAuthToken_DB:
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
    db_token = OAuthToken_DB(**token.model_dump())
    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)
    return db_token


# ------- Read ------- #


async def get_oauth_token(
    db: AsyncSession,
    provider: str,
    user_uuid: str,
    raise_error: bool = True
) -> OAuthToken_DB:
    """
    Get an OAuth token by provider name for a user.

    :param Session db: The current database session.
    :param str provider: The name of the provider of the OAuth token to retrieve.
    :param str user_uuid: The UUID of the user owning the OAuth token.
    :param bool raise_error: Whether to raise an error if the token is not found (default: True).
    :return OAuthToken_DB: The retrieved OAuth token model object.
    :raises HTTPException: If the token is not found and `raise_error` is `True`.
    """
    result = await db.execute(select(OAuthToken_DB).filter(
        OAuthToken_DB.provider == provider,
        OAuthToken_DB.user_uuid == user_uuid
    ))
    db_token = result.unique().scalars().first()
    if not db_token and raise_error:
        raise HTTPException(status_code=404, detail="Token not found")
    return db_token


# ------- Update ------- #


async def update_oauth_token(db: AsyncSession, db_token: OAuthToken_DB, token: OAuthTokenBase) -> OAuthToken_DB:
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
    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)
    return db_token


# ------- Delete ------- #


async def delete_oauth_token(db: AsyncSession, oauth_token: OAuthToken_DB) -> bool:
    """
    Delete an OAuth token from the database.

    This function removes an OAuth token and its associated user link
    from the database. It commits the changes and returns a boolean
    indicating success.

    :param Session db: The current database session.
    :param OAuthToken_DB oauth_token: The OAuth token model object to delete.
    :return bool: True if the operation is successful.
    """
    await db.delete(oauth_token)
    await db.commit()
    return True


# ----- authlib OAuth client functions ----- #


async def fetch_token(provider, request) -> dict:
    """
    Fetch an OAuth token from the database.

    This function is used by authlib as the fetch_token function
    for the OAuth client.

    :param provider: The name of the provider of the OAuth client
    :param request: The request object
    :return: The OAuth token as a dictionary
    """
    async with sessionmanager.session() as db:
        user_uuid = request.session.get("user_uuid")
        if not user_uuid:
            return None
        result = await db.execute(select(OAuthToken_DB).filter(
            OAuthToken_DB.provider == provider,
            OAuthToken_DB.user_uuid == user_uuid
        ))
        item = result.unique().scalar()
        if not item:
            return None
        token = OAuthTokenBase(**item)
    return token.to_token()


async def update_token(provider, token, refresh_token=None, access_token=None):
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
    logger.debug(f"Updating token: {provider}")
    async with sessionmanager.session() as db:
        if refresh_token:
            result = await db.execute(select(OAuthToken_DB).filter(
                OAuthToken_DB.provider == provider,
                OAuthToken_DB.refresh_token == refresh_token
            ))
            item = result.unique().scalar()
        elif access_token:
            result = await db.execute(select(OAuthToken_DB).filter(
                OAuthToken_DB.provider == provider,
                OAuthToken_DB.access_token == access_token
            ))
            item = result.unique().scalar()
        else:
            return

        # update old token
        item.access_token = token['access_token']
        item.refresh_token = token.get('refresh_token')
        item.expires_at = token['expires_at']
        db.add(item)
        await db.commit()
        await db.refresh(item)
