"""
This module contains functions to interact with the database, including
connection management, session creation, and database management using
Alembic migrations.
"""
import logging
import os
import shutil
from typing import Generator
import alembic
from fastapi import HTTPException
from sqlalchemy import (
    Connection, Engine, Inspector, MetaData, Table,
    create_engine, inspect, select, text, update
)
from sqlalchemy.orm import Session, sessionmaker
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext

from app.core.config import settings, logger
from app.core.utils import app_path

engine = create_engine(url=settings.SQLALCHEMY_DATABASE_URI)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    """
    Generator to provide a database session to FastAPI requests.

    This is a dependency that can be injected into FastAPI endpoints. It
    provides a database session that is properly closed at the end of the
    request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def run_migrations() -> None:
    """
    Run Alembic migrations to the latest version.

    This function is meant to be called at application startup. It configures
    Alembic with the `alembic.ini` file and upgrades the database to the latest
    version. The logger is temporarily disabled to prevent logging while the
    migrations are being run.

    The function blocks until the migrations are complete.
    """
    # alembic_cfg = Config("alembic.ini")
    alembic_cfg = Config(
        app_path(os.path.join("app", "alembic.ini")),
        config_args={
            "script_location": app_path(os.path.join("app", "alembic")),
        }
        )
    logger.info("Running Alembic migrations...")
    script = ScriptDirectory.from_config(alembic_cfg)
    head = str(script.get_current_head())
    with engine.connect() as conn:
        context = MigrationContext.configure(conn)
        current = context.get_current_revision()
    if head != current:
        # logger.info("Backing up database...")
        # db = next(get_db())
        # try:
        #     path = await export_db(db, f"../data/backup-{int(time.time())}.db")
        # finally:
        #     db.close()
        # logger.info("Backing up database completed. You can find the backup in the `%s` file.", path)
        command.upgrade(alembic_cfg, "head")
    else:
        logger.info("Database already up-to-date.")
    logger.disabled = False
    logging.getLogger("uvicorn.access").disabled = False
    logger.info("Alembic migrations completed.")


async def handle_database_import(uploaded_db_path: str, mode: str) -> bool:
    """
    Handles importing a database from an uploaded SQLite file.

    The function takes an uploaded SQLite database file path and a mode string as arguments.
    The mode string can be either "recover" or "import".

    In "recover" mode, the function will replace all existing data in the current database
    with the data from the uploaded database. If a row does not exist in the current database,
    it will be added. If a row exists, its data will be replaced with the data from the
    uploaded database if the data is different.

    In "import" mode, the function will not replace existing data in the current database.
    If a row does not exist in the current database, it will be added. If a row exists, its
    data will not be replaced with the data from the uploaded database.

    The function returns a boolean indicating whether the import was successful.

    After the import is complete, the uploaded database file is removed.
    """
    upload_conn, upload_engine = await connect_to_uploaded_db(uploaded_db_path)
    inspector, upload_inspector = await get_inspectors(upload_conn)

    with Session(engine) as session:
        for table_name in inspector.get_table_names():
            if table_name not in upload_inspector.get_table_names():
                # Skip tables not present in the uploaded database
                continue
            await process_table(session, table_name, upload_conn, inspector, mode)

    upload_conn.close()
    upload_engine.dispose()
    return True


async def connect_to_uploaded_db(uploaded_db_path: str) -> tuple[Connection, Engine]:
    """
    Connect to the uploaded SQLite database.
    """
    new_engine = create_engine(f"sqlite:///{uploaded_db_path}")
    new_conn = new_engine.connect()
    return new_conn, new_engine


async def get_inspectors(upload_conn: Connection) -> tuple[Inspector, Inspector]:
    """
    Get the metadata and inspector of the running and uploaded databases.
    """
    meta = MetaData()
    meta.reflect(bind=engine)

    upload_meta = MetaData()
    upload_meta.reflect(bind=upload_conn)

    inspector = inspect(engine)
    upload_inspector = inspect(upload_conn)

    return inspector, upload_inspector


async def process_table(
    session: Session,
    table_name: str,
    upload_conn: Connection,
    inspector: Inspector,
    # upload_inspector: Inspector,
    mode: str
) -> None:
    """
    Process a table by comparing rows based on primary keys.

    The function takes a session, table name, inspectors of the running and uploaded
    databases, and a mode string as arguments.

    If a row does not exist in the current database, it will be added. If a row exists, its
    data will be replaced with the data from the uploaded database if the data is different.
    """
    primary_keys = inspector.get_pk_constraint(
        table_name).get('constrained_columns')

    rows_existing = {tuple(row[key] for key in primary_keys):
                     row for row in session.execute(
                         select(Table(table_name, MetaData(),
                                autoload_with=engine))
    ).mappings()}
    rows_uploaded = {tuple(row[key] for key in primary_keys):
                     row for row in upload_conn.execute(
                         select(Table(table_name, MetaData(),
                                autoload_with=upload_conn))
    ).mappings()}

    for pk, row_uploaded in rows_uploaded.items():
        if pk not in rows_existing:
            # Row does not exist in the existing DB, add it
            new_row = {
                key["name"]: row_uploaded[key["name"]] for key in list(inspector.get_columns(table_name))}
            session.execute(
                Table(table_name, MetaData(), autoload_with=engine).insert().values(new_row))
        else:
            # Row exists, check data differences
            row_existing = rows_existing[pk]
            for col in inspector.get_columns(table_name):
                if col["name"] in list(row_uploaded) and col["name"] in list(row_existing):
                    if mode == "recover" and (
                        row_uploaded[col["name"]] is not None and row_uploaded[col["name"]
                                                                               ] != row_existing[col["name"]]
                    ):
                        # In 'recover', replace data if different
                        # Insert missing rows
                        table = Table(table_name, MetaData(),
                                      autoload_with=engine)
                        stmt = update(table).where(table.c[primary_keys[0]] == pk[0]).values(
                            {col["name"]: row_uploaded[col["name"]]}
                        )
                        session.execute(stmt)
                    elif mode == "import" and (
                        row_existing[col["name"]
                                     ] is None and row_uploaded[col["name"]] is not None
                    ):
                        # In 'import', do not replace existing data
                        table = Table(table_name, MetaData(),
                                      autoload_with=engine)
                        stmt = update(table).where(table.c[primary_keys[0]] == pk[0]).values(
                            {col["name"]: row_uploaded[col["name"]]}
                        )
                        session.execute(stmt)
    # Commit changes
    session.commit()


async def export_db(db: Session, path = None) -> str:
    """
    Export the current database to a file.

    Args:
        db (Session): The database session.

    Returns:
        str: The path to the exported database file.

    Raises:
        HTTPException: If the database file is not found.
    """
    export_path = path or "./output.db"
    if "sqlite" in str(engine.url):
        # If it's SQLite, serve the actual database file
        engine_db_path = engine.url.database
        if os.path.exists(engine_db_path):
            shutil.copyfile(engine_db_path, export_path)
        else:
            raise HTTPException(
                status_code=404, detail="SQLite database file not found.")
    else:
        # For non-SQLite databases, dump the SQL statements
        metadata = MetaData()
        metadata.reflect(bind=engine)  # Reflect the database schema
        with open(export_path, "w", encoding="utf-8") as file:
            # Write schema first
            for table in reversed(metadata.sorted_tables):
                file.write(str(table))
                file.write("\n\n")

            # Write data
            for table in metadata.sorted_tables:
                result = db.execute(text(f"SELECT * FROM {table.name}"))
                rows = result.fetchall()
                if rows:
                    columns = ", ".join(list(result.keys()))
                    for row in rows:
                        values = ", ".join([f"'{str(val)}'" for val in row])
                        insert_stmt = f"INSERT INTO {
                            table.name} ({columns}) VALUES ({values});\n"
                        file.write(insert_stmt)
    return export_path
