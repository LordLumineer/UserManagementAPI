import os
from fastapi.exceptions import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.templates.models import File as File_Model
from app.templates.models import users_files_links
from app.templates.schemas.file import FileReadDB

def get_files(db: Session, skip: int = 0, limit: int = 100) -> list[FileReadDB]:
    return db.query(FileReadDB).offset(skip).limit(limit).all()

def get_file(db: Session, file_id: int) -> FileReadDB:
    db_file = db.query(FileReadDB).filter(FileReadDB.id == file_id).first()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")
    return db_file

# Create File

# Update File

def delete_file(db: Session, file_id: int) -> bool:
    db_file = get_file(db, file_id)
    db.delete(db_file)
    
    # delete from links
    db.execute(delete(users_files_links).where(
        users_files_links.c.file_id == file_id
    ))
    # ... other links related to the file
    try:
        os.remove(db_file.file_path)
        db.commit()
    except OSError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete file. {e.strerror}") from e
    return True

# ----- Helper functions ----- #

def get_files_list(db: Session, id_list: list[int]) -> list[FileReadDB]:
    return db.query(File_Model).filter(File_Model.id.in_(id_list)).all()


def get_file_users_uuid(db: Session, file_id: int) -> list[str]:
    stmt = select(users_files_links.c.user_uuid).where(
        users_files_links.c.file_id == file_id)
    result = db.execute(stmt)
    return [row[0] for row in result]
