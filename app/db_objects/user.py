import os
import time
from fastapi import Depends, HTTPException
from sqlalchemy import delete
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.config import logger
from app.core.db import get_db
from app.core.email import send_validation_email
from app.db_objects.external_account import delete_external_account
from app.db_objects.file import delete_file, get_file_users
from app.db_objects.oauth import delete_oauth_token
from app.core.security import (
    TokenData, create_access_token, decode_access_token,
    generate_otp, hash_password, oauth2_scheme
)
from app.db_objects.db_models import User as User_DB
from app.db_objects.db_models import users_files_links, users_external_accounts_links, users_oauth_tokens_links
from app.templates.schemas.user import UserCreate, UserUpdate


# ~~~~~ CRUD ~~~~~ #


# ------- Create ------- #


async def create_user(db: Session, user: UserCreate) -> User_DB:
    """
    Create a new user.

    If a user with the same email already exists and is external only, then update that user with the provided password and set is_external_only to False.

    :param Session db: The current database session.
    :param UserCreate user: The user to create.
    :return User_DB: The created user model object.
    :raises HTTPException: If a database integrity error occurs.
    """
    try:
        db_user = User_DB(**user.model_dump())
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        os.makedirs(os.path.join("..", "data", "files", db_user.uuid), exist_ok=True)
    except IntegrityError as e:
        db.rollback()
        # Check if the email is already taken, if so, and the user is external only then update
        if str(e.orig).startswith('UNIQUE') and str(e.orig).endswith('users.email'):
            existing_user = get_user_by_email(db, user.email)
            if not existing_user.is_external_only:
                raise HTTPException(
                    status_code=400,
                    detail="Email already taken"
                ) from e
            db_user = await update_user(
                db,
                existing_user,
                UserUpdate(
                    email=user.email,
                    password=user.password,
                    is_external_only=False
                )
            )
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    email_token = create_access_token(
        sub=TokenData(
            purpose="email-verification",
            uuid=db_user.uuid,
            email=db_user.email
        ))
    await send_validation_email(db_user.email, email_token)
    return db_user


# ------- Read ------- #


def get_user(db: Session, uuid: str) -> User_DB:
    """
    Get a user by its UUID.

    :param Session db: The current database session.
    :param str uuid: The UUID of the user to get.
    :return User_DB: The user model object.
    :raises HTTPException: If the user is not found.
    """
    db_user = db.query(User_DB).filter(User_DB.uuid == uuid).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


def get_users(db: Session, skip: int = 0, limit: int = 100) -> list[User_DB]:
    """
    Get a list of users with pagination.

    :param Session db: The current database session.
    :param int skip: The number of items to skip (default is 0).
    :param int limit: The maximum number of items to return (default is 100).
    :return list[User_DB]: A list of user objects.
    """
    return db.query(User_DB).offset(skip).limit(limit).all()


def get_nb_users(db: Session) -> int:
    """
    Get the number of users.

    :param Session db: The current database session.
    :return int: The number of users.
    """
    return db.query(User_DB).count()


def get_users_list(db: Session, id_list: list[str]) -> list[User_DB]:
    """
    Get a list of users based on their UUIDs.

    :param Session db: The current database session.
    :param list[str] id_list: The UUIDs of the users to get.
    :return list[User_DB]: A list of user objects.
    """
    return db.query(User_DB).filter(User_DB.uuid.in_(id_list)).all()


# ** Specific User (Username, Email) ** #


def get_user_by_username(db: Session, username: str) -> User_DB:
    """
    Get a user by its username.

    :param Session db: The current database session.
    :param str username: The username of the user to get.
    :return User_DB: The user model object.
    :raises HTTPException: If the user is not found.
    """
    db_user = db.query(User_DB).filter(
        User_DB.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


def get_user_by_email(db: Session, email: str) -> User_DB:
    """
    Get a user by its email.

    :param Session db: The current database session.
    :param str email: The email of the user to get.
    :return User_DB: The user model object.
    :raises HTTPException: If the user is not found.
    """

    db_user = db.query(User_DB).filter(User_DB.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


# ------- Update ------- #


async def update_user(db: Session, db_user: User_DB, user: UserUpdate) -> User_DB:
    """
    Update an existing user's information.

    This function updates the user information in the database based on the provided
    `UserUpdate` data. If the email of the user is changed, the email verification
    status is reset and a new verification email is sent. If the user is the default
    admin, an OTP is regenerated.

    :param Session db: The current database session.
    :param User_DB db_user: The existing user object to be updated.
    :param UserUpdate user: The new data for the user update.
    :return User_DB: The updated user object.
    :raises HTTPException: If there is an integrity error during the database transaction.
    """
    # Re-Generate the OTP for the default admin user
    # (triggered when the email is updated at first login)
    if db_user.email == "admin@example.com":
        await generate_otp(
            user_uuid=db_user.uuid,
            user_username=db_user.username,
            user_otp_secret=db_user.otp_secret
        )
    # Check if the email has changed
    email_to_verify = False
    if user.email and user.email != db_user.email:
        user.email_verified = False
        email_to_verify = True

    # Update the user
    user_data = user.model_dump(exclude_unset=True, exclude_none=True)
    for key, value in user_data.items():
        setattr(db_user, key, value)
    setattr(db_user, "updated_at", int(time.time()))
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e

    # Send email verification if the email has changed
    if email_to_verify:
        email_token = create_access_token(
            sub=TokenData(
                purpose="email-verification",
                uuid=db_user.uuid,
                email=db_user.email
            ))
        await send_validation_email(db_user.email, email_token)
    return db_user


# ------- Delete ------- #


def delete_user(db: Session, user: User_DB) -> bool:
    """
    Delete a user from the database.

    This function deletes a user, their files, OAuth tokens, and External Accounts from the database.
    It also removes the links between the user and the files, OAuth tokens, and External Accounts.
    This function commits the changes and returns a boolean indicating success.

    :param Session db: The current database session.
    :param User_DB user: The user model object to delete.
    :return bool: True if the operation is successful.
    """
    # Delete the user's files
    db.execute(
        delete(users_files_links).where(
            users_files_links.c.user_uuid == user.uuid)
    )
    for file in user.files:
        # NOTE: Add to the if condition for other tables to check
        if get_file_users(db, file):
            continue
        delete_file(db, file)
    # Delete the user's OAuth tokens
    db.execute(
        delete(users_oauth_tokens_links).where(
            users_oauth_tokens_links.c.user_uuid == user.uuid)
    )
    for oauth_token in user.oauth_tokens:
        delete_oauth_token(db, oauth_token)
    # Delete the user's External Accounts
    db.execute(
        delete(users_external_accounts_links).where(
            users_external_accounts_links.c.user_uuid == user.uuid)
    )
    for external_account in user.external_accounts:
        delete_external_account(db, external_account)
    # Delete the user
    db.delete(user)
    db.commit()
    return True


# ----- Helper Functions ----- #

def get_current_user(token: str = Depends(oauth2_scheme)) -> User_DB:
    """
    Get the current user from the token.

    :param str token: The token from the request header (default is an empty string).
    :return User_DB: The current user object if the token is valid, otherwise raises an HTTPException.
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
            # otp_secret = generate_random_letters(32)
            default_user = User_DB(
                username="admin",
                display_name="Admin",
                email="admin@example.com",
                hashed_password=hash_password("changeme"),
                permission="admin",
                email_verified=True,
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