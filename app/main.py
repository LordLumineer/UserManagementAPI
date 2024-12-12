"""
Main entrypoint of the application

This module contains the main entrypoint of the application. It is responsible
for creating the FastAPI application and setting up the routes and middleware.

# TODO: Check https://unit.nginx.org/howto/fastapi/
"""
from contextlib import asynccontextmanager
import os
# from apscheduler.schedulers.background import BackgroundScheduler
import fastapi
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html
)
from redis import Redis
from redis.exceptions import ConnectionError as RedisConnectionError
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.exc import IntegrityError

from app.api.router import api_router, tags_metadata
from app.api.routes import pages
from app.core import db as database
from app.core.config import settings, logger
from app.core.db import run_migrations
from app.core.permissions import has_permission, load_feature_flags
from app.db_objects.user import get_current_user, init_default_user
from app.core.middleware import FeatureFlagMiddleware, GlobalRateLimiterMiddleware, RedirectUriMiddleware
from app.core.utils import (
    app_path,
    custom_generate_unique_id,
    extract_initials_from_text,
    generate_profile_picture,
)


@asynccontextmanager
async def lifespan(app: FastAPI):  # pragma: no cover   # pylint: disable=unused-argument, redefined-outer-name
    """ Lifespan hook to run on application startup and shutdown. """
    logger.info("Starting up...")
    # Create folders
    logger.info("Creating folders...")
    os.makedirs(app_path(os.path.join("data", "users")), exist_ok=True)
    # os.makedirs(app_path(os.path.join("data", "files")), exist_ok=True)
    if settings.LOG_FILE_ENABLED:
        os.makedirs(app_path(os.path.join("data", "logs")), exist_ok=True)
    # Alembic
    await run_migrations()
    # Database
    logger.info("Creating or Loading the database tables...")
    # Base.metadata.create_all(bind=database.engine)
    await database.sessionmanager.init()
    # Feature Flags
    logger.info("Loading feature flags...")
    app_endpoint_functions_name = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            app_endpoint_functions_name.append(route.endpoint.__name__.upper())
    await load_feature_flags(app_endpoint_functions_name)
    # Rate Limit
    if settings.RATE_LIMITER_ENABLED:
        redis_client = None
        redis_url = settings.REDIS_URL
        if redis_url is not None:
            try:
                redis_client = Redis.from_url(redis_url, decode_responses=True)
                redis_client.ping()
                logger.info("Redis available.")
            except RedisConnectionError:
                redis_client = None
                logger.warning("Redis unavailable. Using in-memory TTL cache.")
            except ValueError as e:
                redis_client = None
                logger.warning(
                    f"Redis unavailable. Using in-memory TTL cache. Error: {e}")
        app.state.redis_client = redis_client
    # Scheduler
    # scheduler = BackgroundScheduler()
    # scheduler.add_job(remove_expired_transactions, 'cron', hour=0, minute=0)
    # scheduler.start()
    # Init Default User Database
    await init_default_user()
    logger.success("Initialization completed.")
    yield  # This is when the application code will run
    logger.info("Shutting down...")
    # DATABASE
    if database.sessionmanager.engine is not None:
        # Close the DB connection
        await database.sessionmanager.close()
    logger.info("Shutting down...")
    # SCHEDULER
    # scheduler.shutdown()
    logger.info("Shutdown completed.")


app = FastAPI(
    debug=settings.LOG_LEVEL == "DEBUG",
    title=settings.PROJECT_NAME,
    # TODO: Write Summary and Description
    summary="A short summary of the API.",
    description="""
A description of the API. Supports Markdown (using [CommonMark syntax](https://commonmark.org/)).

It will be added to the generated OpenAPI (e.g. visible at `/docs`).

Read more in the [FastAPI docs for Metadata and Docs URLs](https://fastapi.tiangolo.com/tutorial/metadata/#metadata-for-api).
""",
    version="0.0.0",
    openapi_tags=tags_metadata,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
    terms_of_service=f"{settings.FRONTEND_URL}/terms",
    contact={
        "name": settings.CONTACT_EMAIL.split("@")[0] if settings.CONTACT_EMAIL else "Contact",
        "url": f"{settings.FRONTEND_URL}/contact",
        "email": settings.CONTACT_EMAIL,
    },
    license_info={
        "name": "Apache 2.0",
        "identifiers": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0",
    },
    generate_unique_id_function=custom_generate_unique_id,
    logger=logger,
)

app.include_router(api_router, prefix=settings.API_STR)
app.include_router(pages.router, tags=["PAGES"])


# NOTE: The order of the middlewares is important
# It's in reverse order of execution (Session->CORS->RateLimiter->FeatureFlag->RedirectUri)
app.add_middleware(RedirectUriMiddleware)
app.add_middleware(FeatureFlagMiddleware)

if settings.RATE_LIMITER_ENABLED:
    app.add_middleware(
        GlobalRateLimiterMiddleware,
        max_requests=settings.RATE_LIMITER_MAX_REQUESTS,
        window_seconds=settings.RATE_LIMITER_WINDOW_SECONDS,
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=settings.JWT_SECRET_KEY)


app.mount(f"{settings.API_STR}/static",
          StaticFiles(directory=app_path("assets")), name="Assets")
# ** ~~~~~ Debugging ~~~~~ ** #


# ----- Exceptions Handler ----- #


@app.exception_handler(IntegrityError)
async def _catch_integrity_error(request: Request, exc: IntegrityError):   # pragma: no cover   # pylint: disable=unused-argument
    # NOTE: Handle IntegrityError and pretty-up the error message
    exc = str(exc.orig)
    if exc.startswith("UNIQUE"):
        raise HTTPException(
            status_code=400,
            detail=f"This {
                exc.split(' ')[-1]} already exists.",  # pylint: disable=C0207
        )
    raise HTTPException(status_code=400, detail=exc)


@app.exception_handler(Exception)
async def _debug_exception_handler(request: Request, exc: Exception):  # pragma: no cover   # pylint: disable=unused-argument
    logger.critical(exc)
    if isinstance(exc, HTTPException):
        if exc.status_code != 500:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    raise HTTPException(
        status_code=500,
        detail=jsonable_encoder({
            "error": str(exc),
            "support": f"{settings.FRONTEND_URL}/support",
            "contact": settings.CONTACT_EMAIL
        })
    )


# ----- DOCS ----- #

@app.get("/interactive-docs", tags=["DOCS"], include_in_schema=False)
async def _custom_swagger_ui_html(request: Request, token: str | None = None):
    if not settings.PROTECTED_INTERACTIVE_DOCS:
        return get_swagger_ui_html(
            openapi_url=app.openapi_url,
            title=app.title + " - Interactive UI",
            swagger_favicon_url=request.url_for("_favicon")
        )
    if not token:
        uri_list = request.session.get("redirect_uri") or []
        uri_list.append(str(request.url_for("_custom_swagger_ui_html")))
        request.session.update({"redirect_uri": uri_list})
        return RedirectResponse(url=request.url_for("_login"))
    current_user = await get_current_user(token)
    if has_permission(current_user, "docs", "swagger", raise_error=False):
        return get_swagger_ui_html(
            openapi_url=app.openapi_url,
            title=app.title + " - Interactive UI",
            swagger_favicon_url=request.url_for("_favicon"),
        )
    return RedirectResponse(url=request.url_for("_redoc_html"))


@app.get(app.swagger_ui_oauth2_redirect_url, tags=["DOCS"], include_in_schema=False)
def _swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()


@app.get("/docs", tags=["DOCS"], include_in_schema=False)
def _redoc_html(request: Request):
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=app.title + " - ReDoc",
        redoc_favicon_url=request.url_for("_favicon"),
    )


# ----- Debugging ----- #

# from app.core.permissions import feature_flag
@app.get("/ping", tags=["DEBUG"])
# @feature_flag("_PING")
def _ping():
    logger.info("Pong!")
    return "pong"


@app.get("/machine", tags=["DEBUG"])
def _machine():
    return JSONResponse(jsonable_encoder(settings.MACHINE))


@app.get("/repository", tags=["DEBUG"])
def _repository():
    return JSONResponse(jsonable_encoder(settings.REPOSITORY))


@app.get("/version", tags=["DEBUG"])
def _version():
    return JSONResponse(jsonable_encoder({
        "FastAPI_Version": fastapi.__version__,
        "Project_Version": app.version,
        "Python_Version": settings.MACHINE["python_version"],
    }))


@app.get(
    "/favicon.ico", tags=["DEBUG"],
    response_class=FileResponse,
    include_in_schema=False
)
def _favicon():
    if os.path.exists(app_path(os.path.join("assets", "favicon.ico"))):
        return FileResponse(app_path(os.path.join("assets", "favicon.ico")))
    if os.path.exists(app_path(os.path.join("assets", "logo.png"))):
        return FileResponse(app_path(os.path.join("assets", "logo.png")))
    letters = extract_initials_from_text(settings.PROJECT_NAME)
    return generate_profile_picture(letters)


@app.get(
    "/logo.png", tags=["DEBUG"],
    response_class=FileResponse,
    include_in_schema=False
)
def _logo():
    if os.path.exists(app_path(os.path.join("assets", "logo.png"))):
        return FileResponse(app_path(os.path.join("assets", "logo.png")))
    if os.path.exists(app_path(os.path.join("assets", "favicon.ico"))):
        return FileResponse(app_path(os.path.join("assets", "favicon.ico")))
    letters = extract_initials_from_text(settings.PROJECT_NAME)
    return generate_profile_picture(letters)


# ** ----- Frontend ----- ** #

@app.get("/redirect_uri", tags=["UTILS"], response_class=RedirectResponse)
def redirect_uri(request: Request, uri: str | None = None):
    """
    Redirects the user to a specified URI or a stored session URI.

    Parameters
    ----------
    request : Request
        The request object containing session data.
    uri : str | None, optional
        The URI to redirect to, if provided.

    Returns
    -------
    RedirectResponse
        A response that redirects the user to the specified or stored URI. If no URI is found,
        redirects to the index page.
    """
    authorization_token = request.headers.get("Authorization")
    if uri:
        return RedirectResponse(url=uri)
    uri_list = request.session.get("redirect_uri")
    if uri_list:
        uri = uri_list.pop()
        request.session.update({"redirect_uri": uri_list})
    uri = uri or request.url_for("_index")
    logger.debug(f"Redirecting to {uri}")
    if authorization_token and (
        str(uri).endswith("/interactive-docs")
    ):
        return RedirectResponse(url=f"{uri}?token={authorization_token}")
    return RedirectResponse(url=uri)
