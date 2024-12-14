"""
This module contains functions to interact with the database, including
connection management, session creation, and database management using
Alembic migrations.
"""
import contextlib
import logging
import os
import shutil
from typing import AsyncIterator, Any
import aiofiles
from fastapi import HTTPException
from sqlalchemy import (
    Connection, Engine, Inspector, MetaData, Table,
    create_engine, inspect, select, text, update
)
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncSession,
    async_sessionmaker,
    create_async_engine
)

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext

from app.core.config import settings, logger
from app.core.utils import app_path
from app.db_objects._base import Base


class DatabaseSessionManager:
    """This class manages the database connections and sessions."""

    def __init__(self, host: str, engine_kwargs: dict[str, Any] = None):
        """
        Create a new instance of the DatabaseSessionManager.

        :param host: The URL of the database to connect to.
        :param engine_kwargs: Optional keyword arguments to pass to the
            `create_async_engine` function.
        """
        if engine_kwargs is None:
            engine_kwargs = {}
        self.engine = create_async_engine(host, **engine_kwargs)
        self.sync_engine = create_engine(host.replace("+aiosqlite", ""))
        self._sessionmaker = async_sessionmaker(
            expire_on_commit=False,
            autocommit=False,
            bind=self.engine
        )

    async def init(self):
        """
        Initialize the database by creating all tables.

        This function is idempotent. If the tables already exist, it will not
        raise an error.
        """
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self):
        """
        Close the database connection and free up all resources.

        This function should be called when the application is shutting down.
        After calling this function, the `DatabaseSessionManager` is no longer
        usable.

        :raises HTTPException: If the database is not initialized.
        """
        if self.engine is None:
            logger.error("DatabaseSessionManager is not initialized")
            raise HTTPException(
                status_code=500,
                detail="DatabaseSessionManager is not initialized"
            )
        await self.engine.dispose()

        self.engine = None
        self._sessionmaker = None

    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncIterator[AsyncConnection]:
        """
        Establish an asynchronous connection to the database.

        This async context manager provides an asynchronous connection to the database.
        It ensures that a connection is established before entering the context and
        properly closed after exiting. If the `DatabaseSessionManager` is not initialized,
        an HTTPException is raised.

        Yields
        ------
        AsyncConnection
            The asynchronous connection object to perform database operations.

        Raises
        ------
        HTTPException
            If the `DatabaseSessionManager` is not initialized.
        """
        if self.engine is None:
            logger.error("DatabaseSessionManager is not initialized")
            raise HTTPException(
                status_code=500,
                detail="DatabaseSessionManager is not initialized"
            )

        async with self.engine.begin() as connection:
            try:
                yield connection
            except Exception:
                await connection.rollback()
                raise

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """
        Establish an asynchronous session to the database.

        This async context manager provides an asynchronous session to the database.
        It ensures that a session is established before entering the context and
        properly closed after exiting. If the `DatabaseSessionManager` is not initialized,
        an HTTPException is raised.

        Yields
        ------
        AsyncSession
            The asynchronous session object to perform database operations.

        Raises
        ------
        HTTPException
            If the `DatabaseSessionManager` is not initialized.
        """
        if self._sessionmaker is None:
            logger.error("DatabaseSessionManager is not initialized")
            raise HTTPException(
                status_code=500,
                detail="DatabaseSessionManager is not initialized"
            )

        session = self._sessionmaker()
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


sessionmanager = DatabaseSessionManager(
    settings.SQLALCHEMY_DATABASE_URI, {"echo": False})


async def get_async_db():
    """
    Get an asynchronous database session.

    This async generator provides an asynchronous session to the database.
    It ensures that a session is established before entering the context and
    properly closed after exiting. The session is usable within the context
    manager.

    Yields
    ------
    AsyncSession
        The asynchronous session object to perform database operations.
    """
    async with sessionmanager.session() as session:
        yield session



async def run_migrations() -> None:
    """
    Run Alembic migrations to the latest version.

    This function is meant to be called at application startup. It configures
    Alembic with the `alembic.ini` file and upgrades the database to the latest
    version. The logger is temporarily disabled to prevent logging while the
    migrations are being run.

    The function blocks until the migrations are complete.
    """
    alembic_cfg = Config(
        app_path(os.path.join("app", "alembic.ini")),
        ini_section="alembic-run",
        config_args={
            "script_location": app_path(os.path.join("app", "alembic")),
        }
    )
    logger.info("Running Alembic migrations...")

    def _run_upgrade(connection, cfg):
        cfg.attributes["connection"] = connection
        script = ScriptDirectory.from_config(alembic_cfg)
        head = str(script.get_current_head())
        context = MigrationContext.configure(connection)
        current = context.get_current_revision()
        if head != current:
            command.upgrade(cfg, "head")
        else:
            logger.info("Database already up-to-date.")
    async with sessionmanager.connect() as conn:
        await conn.run_sync(_run_upgrade, alembic_cfg)

    # Reactivate FastAPI LOGGER (Uvicorn)
    for _logger in logging.root.manager.loggerDict.values():  # pylint: disable=E1101
        if isinstance(_logger, logging.Logger):
            if "uvicorn" in _logger.name:
                _logger.disabled = False

    logger.success("Alembic migrations completed.")


def handle_database_import(uploaded_db_path: str, mode: str) -> bool:
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
    upload_conn, upload_engine = connect_to_uploaded_db(uploaded_db_path)
    inspector, upload_inspector = get_inspectors(upload_conn)

    with Session(sessionmanager.sync_engine) as session:
        for table_name in inspector.get_table_names():
            if table_name not in upload_inspector.get_table_names():
                # Skip tables not present in the uploaded database
                continue
            process_table(session, table_name, upload_conn, inspector, mode)

    upload_conn.close()
    upload_engine.dispose()
    return True


def connect_to_uploaded_db(uploaded_db_path: str) -> tuple[Connection, Engine]:
    """
    Connect to the uploaded SQLite database.
    """
    new_engine = create_engine(f"sqlite:///{uploaded_db_path}")
    new_conn = new_engine.connect()
    return new_conn, new_engine


def get_inspectors(upload_conn: Connection) -> tuple[Inspector, Inspector]:
    """
    Get the metadata and inspector of the running and uploaded databases.
    """
    meta = MetaData()
    meta.reflect(bind=sessionmanager.sync_engine)

    upload_meta = MetaData()
    upload_meta.reflect(bind=upload_conn)

    inspector = inspect(sessionmanager.sync_engine)
    upload_inspector = inspect(upload_conn)

    return inspector, upload_inspector


def process_table(
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
                                autoload_with=sessionmanager.sync_engine))
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
                Table(table_name, MetaData(), autoload_with=sessionmanager.sync_engine).insert().values(new_row))
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
                                      autoload_with=sessionmanager.sync_engine)
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
                                      autoload_with=sessionmanager.sync_engine)
                        stmt = update(table).where(table.c[primary_keys[0]] == pk[0]).values(
                            {col["name"]: row_uploaded[col["name"]]}
                        )
                        session.execute(stmt)
    # Commit changes
    session.commit()


async def export_db(db: AsyncSession, path=None) -> str:
    """
    Export the current database to a file.

    Args:
        db (Session): The database session.

    Returns:
        str: The path to the exported database file.

    Raises:
        HTTPException: If the database file is not found.
    """
    export_path = path or app_path("output.db")
    if "sqlite" in str(sessionmanager.engine.url):
        # If it's SQLite, serve the actual database file
        engine_db_path = sessionmanager.engine.url.database
        if os.path.exists(engine_db_path):
            shutil.copyfile(engine_db_path, export_path)
        else:
            raise HTTPException(
                status_code=404, detail="SQLite database file not found.")
    else:
        # For non-SQLite databases, dump the SQL statements
        metadata = MetaData()
        # Reflect the database schema
        metadata.reflect(bind=sessionmanager.sync_engine)
        async with aiofiles.open(export_path, "w", encoding="utf-8") as file:
            # Write schema first
            for table in reversed(metadata.sorted_tables):
                await file.write(str(table))
                await file.write("\n\n")

            # Write data
            for table in metadata.sorted_tables:
                result = await db.execute(text(f"SELECT * FROM {table.name}"))
                rows = result.fetchall()
                if rows:
                    columns = ", ".join(list(result.keys()))
                    for row in rows:
                        values = ", ".join([f"'{str(val)}'" for val in row])
                        insert_stmt = f"INSERT INTO {
                            table.name} ({columns}) VALUES ({values});\n"
                        await file.write(insert_stmt)
    return export_path
