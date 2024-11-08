"""
This module contains functions to interact with third-party account models in the database.

@file: ./app/core/object/third_party_account.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from fastapi.exceptions import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.templates.models import ThirdPartyAccount
from app.templates.schemas.third_party_account import ThirdPartyAccountBase


def get_third_party_account(db: Session, acc_id: str) -> ThirdPartyAccount:
    """
    Get a third party account by its ID.

    :param Session db: The current database session.
    :param str acc_id: The ID of the third party account to get.
    :return ThirdPartyAccount: The third party account object.
    :raises HTTPException: If the third party account is not found.
    """
    db_third_party_account = db.query(ThirdPartyAccount).filter(
        ThirdPartyAccount.acc_id == acc_id).first()
    if not db_third_party_account:
        raise HTTPException(
            status_code=404, detail="Third party account not found")
    return db_third_party_account


def get_third_party_accounts_list(db: Session, id_list: list[str]) -> list[ThirdPartyAccount]:
    """
    Get a list of third party accounts by their IDs.

    :param Session db: The current database session.
    :param list[str] id_list: A list of third party account IDs to get.
    :return list[ThirdPartyAccount]: A list of third party account objects.
    """

    return db.query(ThirdPartyAccount).filter(ThirdPartyAccount.acc_id.in_(id_list)).all()


def create_third_party_account(db: Session, third_party_account: ThirdPartyAccountBase) -> ThirdPartyAccount:
    """
    Create a new third party account in the database.

    :param Session db: The current database session.
    :param ThirdPartyAccountBase third_party_account: The third party account to create.
    :return ThirdPartyAccount: The created third party account object.
    :raises HTTPException: If a database integrity error occurs.
    """
    try:
        db_third_party_account = ThirdPartyAccount(
            **third_party_account.model_dump())
        db.add(db_third_party_account)
        db.commit()
        db.refresh(db_third_party_account)

        # Link User to Third Party Account
        from app.core.object.user import link_third_party_account_to_user  # pylint: disable=import-outside-toplevel
        link_third_party_account_to_user(
            db,
            third_party_account_id=third_party_account.acc_id,
            user_uuid=third_party_account.user_uuid
        )
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    return db_third_party_account


def update_third_party_account(
    db: Session,
    acc_id: str,
    third_party_account: ThirdPartyAccountBase
) -> ThirdPartyAccount:
    """
    Update a third party account by its ID.

    :param Session db: The current database session.
    :param str acc_id: The ID of the third party account to update.
    :param ThirdPartyAccountBase third_party_account: The updated third party account object.
    :return ThirdPartyAccount: The third party account object after update.
    :raises HTTPException: If the third party account is not found, or the update fails.
    """
    db_third_party_account = get_third_party_account(db, acc_id)
    third_party_account_data = third_party_account.model_dump(
        exclude_unset=True, exclude_none=True)
    for field, value in third_party_account_data.items():
        setattr(db_third_party_account, field, value)
    try:
        db.add(db_third_party_account)
        db.commit()
        db.refresh(db_third_party_account)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    return db_third_party_account


def delete_third_party_account(db: Session, acc_id: str) -> bool:
    """
    Delete a third party account by its ID.

    :param Session db: The current database session.
    :param str acc_id: The ID of the third party account to delete.
    :return bool: Whether the deletion was successful.
    :raises HTTPException: If the third party account is not found.
    """
    db_third_party_account = get_third_party_account(db, acc_id)
    db.delete(db_third_party_account)
    db.commit()
    return True
