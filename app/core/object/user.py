"""
This module contains the functions to interact with the users in the database.

@file: ./app/core/object/user.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from fastapi import Depends, HTTPException
from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.config import logger
from app.core.db import get_db
from app.core.email import send_validation_email
from app.core.object.file import delete_file, get_file_users_uuid
from app.core.security import TokenData, create_access_token, decode_access_token, hash_password, oauth2_scheme
from app.templates.models import User as User_Model
from app.templates.models import users_files_links
from app.templates.schemas.user import UserCreate, UserReadDB, UserUpdate


def get_nb_users(db: Session) -> int:
    """
    Get the number of users in the database.

    :param Session db: The current database session.
    :return int: The number of users in the database.
    """
    return db.query(User_Model).count()


def get_users(db: Session, skip: int = 0, limit: int = 100) -> list[UserReadDB]:
    """
    Get a list of users from the database.

    :param Session db: The current database session.
    :param int skip: The number of items to skip (default is 0).
    :param int limit: The maximum number of items to return (default is 100).
    :return list[UserReadDB]: A list of user objects.
    """
    return db.query(User_Model).offset(skip).limit(limit).all()


def get_user(db: Session, uuid: str) -> User_Model:
    """
    Get a user by its UUID.

    :param Session db: The current database session.
    :param str uuid: The UUID of the user to get.
    :return User_Model: The user object.
    :raises HTTPException: If the user is not found
    """
    db_user = db.query(User_Model).filter(User_Model.uuid == uuid).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


def get_user_by_username(db: Session, username: str) -> User_Model:
    """
    Get a user by its username.

    :param Session db: The current database session.
    :param str username: The username of the user to get.
    :return User_Model: The user object.
    :raises HTTPException: If the user is not found
    """
    db_user = db.query(User_Model).filter(
        User_Model.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


def get_user_by_email(db: Session, email: str) -> User_Model:
    """
    Get a user by its email.

    :param Session db: The current database session.
    :param str email: The email of the user to get.
    :return User_Model: The user object.
    :raises HTTPException: If the user is not found
    """
    db_user = db.query(User_Model).filter(User_Model.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


async def create_user(db: Session, user: UserCreate) -> User_Model:
    """
    Create a new user.

    :param Session db: The current database session.
    :param UserCreate user: The user object to create.
    :return User_Model: The new user object.
    :raises HTTPException: If the user already exists
    """
    try:
        db_user = User_Model(**user.model_dump())
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    email_token = create_access_token(
        sub=TokenData(
            purpose="login",
            uuid=db_user.uuid,
            permission=db_user.permission
        ))
    await send_validation_email(db_user.email, email_token)
    return db_user


async def update_user(db: Session, uuid: str, user: UserUpdate) -> User_Model:
    """
    Update a user by its UUID.

    :param Session db: The current database session.
    :param str uuid: The UUID of the user to update.
    :param UserUpdate user: The user object with the updated data.
    :return User_Model: The updated user object.
    :raises HTTPException: If the user is not found, or if the email is taken
    """
    db_user = get_user(db, uuid)
    email_to_verify = False
    if user.email and user.email != db_user.email:
        user.email_verified = False
        email_to_verify = True
    user_data = user.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in user_data.items():
        setattr(db_user, key, value)
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    if email_to_verify:
        email_token = create_access_token(
            sub=TokenData(
                purpose="email-verification",
                uuid=db_user.uuid,
                email=db_user.email
            ))
        await send_validation_email(db_user.email, email_token)
    return db_user


def delete_user(db: Session, uuid: str) -> bool:
    """
    Delete a user by its UUID.

    :param Session db: The current database session.
    :param str uuid: The UUID of the user to delete.
    :return bool: True if the user is deleted successfully, otherwise False.
    """
    db_user = get_user(db, uuid)
    db.delete(db_user)
    db.execute(delete(users_files_links).where(
        users_files_links.c.user_uuid == uuid))
    for file_id in db_user.files_id:
        if get_file_users_uuid(db, file_id):
            continue
        delete_file(db, file_id)
    db.commit()
    return True


# ----- Helper Functions ----- #


def get_current_user(token: str = Depends(oauth2_scheme)) -> User_Model:
    """
    Get the current user from the token.

    :param str token: The token from the request header (default is an empty string).
    :return User_Model: The current user object if the token is valid, otherwise raises an HTTPException.
    """
    token_data = decode_access_token(token, strict=False)
    if token_data.purpose != "login":
        raise HTTPException(status_code=401, detail="Unauthorized")
    db = next(get_db())
    try:
        user = get_user(db, token_data.uuid)
        if user.permission != token_data.permission:
            raise HTTPException(status_code=401, detail="Unauthorized")
    except HTTPException as e:
        raise e
    finally:
        db.close()
    return user


def get_users_list(db: Session, id_list: list[str]) -> list[User_Model]:
    """
    Get a list of users based on their UUIDs.

    :param Session db: The current database session.
    :param list[str] id_list: A list of user UUIDs.
    :return list[User_Model]: A list of user objects.
    """
    return db.query(User_Model).filter(User_Model.uuid.in_(id_list)).all()


def get_user_files_id(db: Session, user_uuid: str) -> list[int]:
    """
    Get a list of file IDs associated with a user.

    :param Session db: The current database session.
    :param str user_uuid: The UUID of the user to get the file IDs of.
    :return list[int]: A list of file IDs associated with the user.
    """
    stmt = select(users_files_links.c.file_id).where(
        users_files_links.c.user_uuid == user_uuid)
    result = db.execute(stmt)
    return [row[0] for row in result]


def link_file_to_user(db: Session, user_uuid: str, file_id: int) -> int:
    """
    Link a file to a user.

    :param Session db: The current database session.
    :param str user_uuid: The UUID of the user to link the file to.
    :param int file_id: The ID of the file to link.
    :return int: The ID of the file that was linked.
    """
    db.execute(
        insert(users_files_links).values(user_uuid=user_uuid, file_id=file_id)
    )
    db.commit()
    return file_id


def delete_user_file(db: Session, user_uuid: str, file_id: int) -> list[int]:
    """
    Delete a file from a user's list of files.

    :param Session db: The current database session.
    :param str user_uuid: The UUID of the user to delete the file from.
    :param int file_id: The ID of the file to delete.
    :return list[int]: A list of file IDs associated with the user.
    """
    db.execute(
        delete(users_files_links).where(
            users_files_links.c.user_uuid == user_uuid,
            users_files_links.c.file_id == file_id
        )
    )
    db.commit()
    if not get_file_users_uuid(db, file_id):
        delete_file(db, file_id)
    return get_user_files_id(db, user_uuid)


def init_default_user() -> None:
    """
    Initialize the default user.

    If there are no users in the database, create a default user with the following details:

    - Username: admin
    - Email: admin@example.com
    - Password: changeme
    - Permission: admin
    - Email verified: True
    - OTP secret: changeme

    A warning is logged with the details of the default user, 
    asking the user to change the default password and email after first login.

    If there are users in the database, do nothing.

    :raises HTTPException: If there is an IntegrityError while creating the default user.
    """
    db = next(get_db())
    try:
        if len(get_users(db)) == 0:
            default_user = User_Model(
                username="admin",
                email="admin@example.com",
                hashed_password=hash_password("changeme"),
                permission="admin",
                email_verified=True,
                # TODO: add in update user if it's the first user change (aka. this one), reset the OTP secret
                otp_secret="changeme",
            )
            db.add(default_user)
            db.commit()
            db.refresh(default_user)
            logger.critical(
                "\nDefault user created:\n\n"
                "    Username: %s\n"
                "    Email: %s\n"
                "    Password: changeme\n"
                "    Permission: %s\n\n"
                "Please change the default password and email after first login.\n",
                default_user.username,
                default_user.email,
                default_user.permission,
            )
    except IntegrityError as e:
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    finally:
        db.close()
