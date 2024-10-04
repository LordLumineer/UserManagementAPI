from fastapi import Depends, HTTPException
from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.config import logger
from app.core.db import get_db
from app.core.object.file import delete_file, get_file_users_uuid
from app.core.security import TokenData, decode_access_token, hash_password, oauth2_scheme
from app.templates.models import User as User_Model
from app.templates.models import users_files_links
from app.templates.schemas.user import UserCreate, UserReadDB, UserUpdate


def get_users(db: Session, skip: int = 0, limit: int = 100) -> list[UserReadDB]:
    return db.query(User_Model).offset(skip).limit(limit).all()


def get_user(db: Session, uuid: str) -> User_Model:
    db_user = db.query(User_Model).filter(User_Model.uuid == uuid).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


def get_user_by_username(db: Session, username: str) -> User_Model:
    db_user = db.query(User_Model).filter(
        User_Model.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


def get_user_by_email(db: Session, email: str) -> User_Model:
    db_user = db.query(User_Model).filter(User_Model.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


def create_user(db: Session, user: UserCreate) -> User_Model:
    try:
        db_user = User_Model(**user.model_dump())
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    # TODO: send verification email
    return db_user


def update_user(db: Session, uuid: str, user: UserUpdate) -> User_Model:
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
        # TODO: send verification email
        pass
    return db_user


def delete_user(db: Session, uuid: str) -> bool:
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
    claims = decode_access_token(token)
    sub: TokenData = TokenData(**claims["sub"])
    db = next(get_db())
    try:
        user = get_user(db, sub.uuid)
        if sub.permission in list(sub.model_dump().keys()):
            if user.permission != sub.permission:
                raise HTTPException(status_code=401, detail="Unauthorized")
    except HTTPException as e:
        raise e
    finally:
        db.close()
    return user


def get_users_list(db: Session, id_list: list[str]) -> list[User_Model]:
    return db.query(User_Model).filter(User_Model.uuid.in_(id_list)).all()


def get_user_files_id(db: Session, user_uuid: str) -> list[int]:
    stmt = select(users_files_links.c.file_id).where(
        users_files_links.c.user_uuid == user_uuid)
    result = db.execute(stmt)
    return [row[0] for row in result]


def link_file_to_user(db: Session, user_uuid: str, file_id: int) -> int:
    db.execute(
        insert(users_files_links).values(user_uuid=user_uuid, file_id=file_id)
    )
    db.commit()
    return file_id


def delete_user_file(db: Session, user_uuid: str, file_id: int) -> list[int]:
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
    db = next(get_db())
    try:
        if len(get_users(db)) == 0:
            default_user = User_Model(
                username="admin",
                email="admin@example.com",
                hashed_password=hash_password("changeme"),
                permission="admin",
                email_verified=True
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
        else:
            return None
    except IntegrityError as e:
        raise HTTPException(status_code=400, detail=str(e.orig)) from e
    finally:
        db.close()
