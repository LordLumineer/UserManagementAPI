"""This module contains functions for CRUD operations on external accounts."""
from fastapi.exceptions import HTTPException
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db_objects.db_models import ExternalAccount as ExternalAccount_DB
from app.templates.schemas.external_account import ExternalAccountBase


# ~~~~~ CRUD ~~~~~ #


# ------- Create ------- #


async def create_external_account(db: AsyncSession, external_account: ExternalAccountBase) -> ExternalAccount_DB:
    """
    Create a new external account and link it to a user.

    This function adds a new external account to the database using the details
    provided in the `external_account` parameter. It also creates an association
    between the user and the external account in the linking table.

    :param Session db: The current database session.
    :param ExternalAccountBase external_account: The external account details to be added.
    :return ExternalAccount_DB: The created external account model object.
    :raises HTTPException: If a database integrity error occurs.
    """
    db_external_account = ExternalAccount_DB(
        **external_account.model_dump())
    db.add(db_external_account)
    await db.commit()
    await db.refresh(db_external_account)
    return db_external_account


# ------- Read ------- #


async def get_external_account(
    db: AsyncSession, provider: str,
    external_account_id: str,
    raise_error: bool = True
) -> ExternalAccount_DB:
    """
    Get an external account by its ID and provider.

    This function retrieves an external account from the database, based on its
    ID and provider.

    :param Session db: The current database session.
    :param str provider: The provider of the external account.
    :param str external_account_id: The ID of the external account.
    :param bool raise_error: If true, raises an exception if the external account is not found.
    :return ExternalAccount_DB: The external account model object.
    :raises HTTPException: If the external account is not found and raise_error is True.
    """
    result = await db.execute(select(ExternalAccount_DB).filter(
        ExternalAccount_DB.external_account_id == external_account_id,
        ExternalAccount_DB.provider == provider))
    db_external_account = result.unique().scalar()
    if not db_external_account and raise_error:
        raise HTTPException(
            status_code=404, detail="External account not found")
    return db_external_account


async def get_external_accounts(db: AsyncSession, skip: int = 0, limit: int = 100) -> list[ExternalAccount_DB]:
    """
    Get a list of external accounts.

    This function retrieves a list of external accounts from the database, with pagination.

    :param Session db: The current database session.
    :param int skip: The number of items to skip (default is 0).
    :param int limit: The maximum number of items to return (default is 100).
    :return list[ExternalAccount_DB]: A list of external account model objects.
    """
    result = await db.execute(select(ExternalAccount_DB).offset(skip).limit(limit))
    return result.unique().scalars().all()


async def get_nb_external_accounts(db: AsyncSession) -> int:
    """
    Get the number of external accounts.

    This function retrieves the total number of external accounts in the database.

    :param Session db: The current database session.
    :return int: The number of external accounts.
    """
    result = await db.execute(text(f"SELECT COUNT(*) FROM {ExternalAccount_DB.__tablename__}"))
    return int(result.unique().scalar())


async def get_external_accounts_list(db: AsyncSession,
                                     external_account_id_list: list[str]) -> list[ExternalAccount_DB]:
    """
    Get a list of external accounts by their IDs.

    This function retrieves a list of external accounts from the database, based on their IDs.

    :param Session db: The current database session.
    :param list[str] external_account_id_list: The IDs of the external accounts to get.
    :return list[ExternalAccount_DB]: A list of external account model objects.
    """
    result = await db.execute(select(ExternalAccount_DB).where(
        ExternalAccount_DB.external_account_id.in_(external_account_id_list)))
    return result.unique().scalars().all()


# ------- Update ------- #


async def update_external_account(
    db: AsyncSession,
    db_external_account: ExternalAccount_DB,
    external_account: ExternalAccountBase
) -> ExternalAccount_DB:
    """
    Update an existing external account in the database.

    This function updates the fields of an existing external account with
    the values provided in the `external_account` parameter. It commits the
    changes to the database and refreshes the external account object to
    reflect the updated state.

    :param Session db: The current database session.
    :param ExternalAccount_DB db_external_account: The existing external account
        model object to update.
    :param ExternalAccountBase external_account: The new external account details
        to update the existing account with.
    :return ExternalAccount_DB: The updated external account model object.
    :raises HTTPException: If a database integrity error occurs.
    """
    external_account_data = external_account.model_dump(
        exclude_unset=True, exclude_none=True)
    for field, value in external_account_data.items():
        setattr(db_external_account, field, value)
    db.add(db_external_account)
    await db.commit()
    await db.refresh(db_external_account)
    return db_external_account


# ------- Delete ------- #


async def delete_external_account(db: AsyncSession, db_external_account: ExternalAccount_DB) -> bool:
    """
    Delete an external account from the database.

    This function removes an external account and its associated link to a user
    from the database. It commits the changes and returns a boolean indicating
    success.

    :param Session db: The current database session.
    :param ExternalAccount_DB db_external_account: The external account model
        object to delete.
    :return bool: True if the operation is successful.
    """
    await db.delete(db_external_account)
    await db.commit()
    return True
