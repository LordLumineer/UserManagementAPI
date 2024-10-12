"""
Main entrypoint of the application

This module contains the main entrypoint of the application. It is responsible
for creating the FastAPI application and setting up the routes and middleware.

@file: ./app/main.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from contextlib import asynccontextmanager
# from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware

from app.api.router import api_router, tags_metadata
from app.core import db as database
from app.core.config import settings, logger
from app.core.db import run_migrations
from app.core.object.user import init_default_user
from app.core.utils import custom_generate_unique_id
from app.templates.base import Base

Base.metadata.create_all(bind=database.engine)


@asynccontextmanager
async def lifespan(app: FastAPI):  # pylint: disable=unused-argument, redefined-outer-name
    """ Lifespan hook to run on application startup and shutdown. """
    logger.info("Starting up...")
    # Alembic
    run_migrations()
    # Init Default User Database
    init_default_user()
    # Scheduler
    # scheduler = BackgroundScheduler()
    # scheduler.add_job(remove_expired_transactions, 'cron', hour=0, minute=0)
    # scheduler.start()
    yield  # This is when the application code will run
    # scheduler.shutdown()
    logger.info("Shutting down...")


app = FastAPI(
    debug=settings.LOG_LEVEL == "DEBUG",
    title=settings.PROJECT_NAME,
    summary="A short summary of the API.",  # TODO
    description="""
# TODO
A description of the API. Supports Markdown (using [CommonMark syntax](https://commonmark.org/)).

It will be added to the generated OpenAPI (e.g. visible at `/docs`).

Read more in the [FastAPI docs for Metadata and Docs URLs](https://fastapi.tiangolo.com/tutorial/metadata/#metadata-for-api).
""",
    version="0.0.0",
    openapi_tags=tags_metadata,
    lifespan=lifespan,
    terms_of_service=f"{settings.FRONTEND_URL}/terms",
    contact={
        "name": settings.CONTACT_EMAIL.split("@")[0],
        "url": f"{settings.FRONTEND_URL}/contact",
        "email": settings.CONTACT_EMAIL,
    },
    license_info={
        "name": "Apache 2.0",
        "identifiers": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0",
    },
    generate_unique_id_function=custom_generate_unique_id,
)

app.include_router(api_router, prefix=settings.API_STR)
app.mount(f"{settings.API_STR}/static",
          StaticFiles(directory="../assets"), name="Assets")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/ping", tags=["DEBUG"])
def ping():
    """Simple healthcheck endpoint to check if the API is alive."""
    logger.info("Pong!")
    return "pong"
