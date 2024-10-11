from contextlib import asynccontextmanager
# from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
# from starlette.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core import db as database
from app.core.config import settings, logger
from app.core.db import run_migrations
from app.core.object.user import init_default_user
from app.templates.base import Base

Base.metadata.create_all(bind=database.engine)

app = FastAPI()


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


def custom_generate_unique_id(route: APIRoute) -> str:
    """Generate a unique ID for a route by combining its first tag with its name."""
    return f"{route.tags[0]}-{route.name}"


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""""",
    version="0.0.0",
    generate_unique_id_function=custom_generate_unique_id,
    lifespan=lifespan,
)

app.include_router(api_router, prefix=settings.API_STR)
app.mount(f"{settings.API_STR}/static",
          StaticFiles(directory="../assets"), name="Assets")
# # app.add_middleware(
# #     CORSMiddleware,
# #     allow_origins=["*"],
# #     allow_credentials=True,
# #     allow_methods=["*"],
# #     allow_headers=["*"],
# # )


@app.get("/ping", tags=["DEBUG"])
def ping():
    """Simple healthcheck endpoint to check if the API is alive."""
    logger.info("Pong!")
    return "pong"
