"""
This module contains functions to interact with third-party account models in the database.

@file: ./app/core/object/external_account.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from fastapi.exceptions import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.templates.models import ExternalAccount
from app.templates.schemas.external_account import ExternalAccountBase

def get_external_account(db: Session, external_acc_id: str) -> ExternalAccount:
    """
    Get a third party account by its ID.

    :param Session db: The current database session.
    :param str external_acc_id: The ID of the third party account to get.
    :return ExternalAccount: The third party account object.
    :raises HTTPException: If the third party account is not found.
    """
    db_external_account = db.query(ExternalAccount).filter(
        ExternalAccount.external_acc_id == external_acc_id).first()
    if not db_external_account:
        raise HTTPException(
            status_code=404, detail="Third party account not found")
    return db_external_account


def get_external_accounts_list(db: Session, id_list: list[str]) -> list[ExternalAccount]:
    """
    Get a list of third party accounts by their IDs.

    :param Session db: The current database session.
    :param list[str] id_list: A list of third party account IDs to get.
    :return list[ExternalAccount]: A list of third party account objects.
    """

    return db.query(ExternalAccount).filter(ExternalAccount.external_acc_id.in_(id_list)).all()


def create_external_account(db: Session, external_account: ExternalAccountBase) -> ExternalAccount:
    """
    Create a new third party account in the database.

    :param Session db: The current database session.
    :param ExternalAccountBase external_account: The third party account to create.
    :return ExternalAccount: The created third party account object.
    :raises HTTPException: If a database integrity error occurs.
    """
    try:
        db_external_account = ExternalAccount(
            **external_account.model_dump())
        db.add(db_external_account)
        db.commit()
        db.refresh(db_external_account)

        # Link User to Third Party Account
        from app.core.object.user import link_external_account_to_user  # pylint: disable=import-outside-toplevel
        link_external_account_to_user(
            db,
            external_account_id=external_account.external_acc_id,
            user_uuid=external_account.user_uuid
        )
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    return db_external_account


def update_external_account(
    db: Session,
    external_acc_id: str,
    external_account: ExternalAccountBase
) -> ExternalAccount:
    """
    Update a third party account by its ID.

    :param Session db: The current database session.
    :param str external_acc_id: The ID of the third party account to update.
    :param ExternalAccountBase external_account: The updated third party account object.
    :return ExternalAccount: The third party account object after update.
    :raises HTTPException: If the third party account is not found, or the update fails.
    """
    db_external_account = get_external_account(db, external_acc_id)
    external_account_data = external_account.model_dump(
        exclude_unset=True, exclude_none=True)
    for field, value in external_account_data.items():
        setattr(db_external_account, field, value)
    try:
        db.add(db_external_account)
        db.commit()
        db.refresh(db_external_account)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    return db_external_account


def delete_external_account(db: Session, external_acc_id: str) -> bool:
    """
    Delete a third party account by its ID.

    :param Session db: The current database session.
    :param str external_acc_id: The ID of the third party account to delete.
    :return bool: Whether the deletion was successful.
    :raises HTTPException: If the third party account is not found.
    """
    db_external_account = get_external_account(db, external_acc_id)
    db.delete(db_external_account)
    db.commit()
    return True
