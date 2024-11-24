"""
Main entrypoint of the application

This module contains the main entrypoint of the application. It is responsible
for creating the FastAPI application and setting up the routes and middleware.

@file: ./app/main.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from contextlib import asynccontextmanager
import os
# from apscheduler.schedulers.background import BackgroundScheduler
import fastapi
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.exc import IntegrityError


from app.api.router import api_router, tags_metadata
from app.core import db as database
from app.core.config import settings, logger
from app.core.db import run_migrations
from app.core.permissions import load_feature_flags
from app.db_objects.user import init_default_user
from app.core.utils import (
    FeatureFlagMiddleware,
    custom_generate_unique_id,
    extract_initials_from_text,
    generate_profile_picture,
    not_found_page,
    render_html_template,
)
from app.db_objects._base import Base


@asynccontextmanager
async def lifespan(app: FastAPI):  # pylint: disable=unused-argument, redefined-outer-name
    """ Lifespan hook to run on application startup and shutdown. """
    logger.info("Starting up...")
    # Create folders
    logger.info("Creating folders...")
    os.makedirs(os.path.join("..", "data", "files", "users"), exist_ok=True)
    os.makedirs(os.path.join("..", "data", "files", "files"), exist_ok=True)
    # Alembic
    await run_migrations()
    # Database
    logger.info("Creating or Loading the database tables...")
    Base.metadata.create_all(bind=database.engine)
    # Feature Flags
    logger.info("Loading feature flags...")
    app_endpoint_functions_name = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            app_endpoint_functions_name.append(route.endpoint.__name__.upper())
    load_feature_flags(app_endpoint_functions_name)
    # Scheduler
    # scheduler = BackgroundScheduler()
    # scheduler.add_job(remove_expired_transactions, 'cron', hour=0, minute=0)
    # scheduler.start()
    # Init Default User Database
    init_default_user()
    logger.info("Initialization completed.")
    yield  # This is when the application code will run
    # scheduler.shutdown()
    logger.info("Shutting down...")


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
    lifespan=lifespan,
    terms_of_service=f"{settings.FRONTEND_URL}/terms",
    contact={
        "name": settings.CONTACT_EMAIL.split("@")[0] if settings.CONTACT_EMAIL else "Unknown",
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
app.add_middleware(SessionMiddleware, secret_key=settings.JWT_SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(FeatureFlagMiddleware)
app.mount(f"{settings.API_STR}/static",
          StaticFiles(directory="../assets"), name="Assets")
# ** ~~~~~ Debugging ~~~~~ ** #

# from app.core.permissions import feature_flag
# @app.get("/me", tags=["DEBUG"])
# @feature_flag("MULTIPLE_ALLOWANCES")
# async def read_user_me():
#     return {"message": "Feature flag enforced!"}
# ----- Exceptions Handler ----- #


@app.exception_handler(IntegrityError)
def _catch_integrity_error(request: Request, exc: IntegrityError):  # pylint: disable=unused-argument
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
def _debug_exception_handler(request: Request, exc: Exception):  # pylint: disable=unused-argument
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


# ----- Debugging ----- #

@app.get("/ping", tags=["DEBUG"])
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
async def _favicon():
    if os.path.exists("../assets/favicon.ico"):
        return FileResponse("../assets/favicon.ico")
    if os.path.exists("../assets/logo.png"):
        return FileResponse("../assets/logo.png")
    letters = extract_initials_from_text(settings.PROJECT_NAME)
    return await generate_profile_picture(letters)


# ** ----- Frontend ----- ** #

# ----- PLACEHOLDER ----- #

@app.get("/", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _index():
    return not_found_page()
    # return RedirectResponse(url=settings.FRONTEND_URL)


@app.get("/terms", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _terms():
    return not_found_page()
    # return RedirectResponse(url=f"{settings.FRONTEND_URL}/terms")


@app.get("/privacy", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _privacy():
    return not_found_page()
    # return RedirectResponse(url=f"{settings.FRONTEND_URL}/privacy")


@app.get("/support", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _support():
    return not_found_page()
    # return RedirectResponse(url=f"{settings.FRONTEND_URL}/support")


# ----- BACK UPs ----- #

@app.get("/login", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _login():
    with open("./templates/html/login_page.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    context = {
        "ENDPOINT": "/auth/login",
    }
    html = render_html_template(html_content, context)
    return HTMLResponse(content=html)


@app.get("/signin", tags=["PAGE"], include_in_schema=False, response_class=RedirectResponse)
def _sign_in():
    return RedirectResponse(url=f"{settings.FRONTEND_URL}/login", status_code=308)


@app.get("/otp", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _otp():
    with open("./templates/html/otp_page.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    context = {
        "ENDPOINT": "/auth/OTP",
        "OTP_LENGTH": settings.OTP_LENGTH,
    }
    html = render_html_template(html_content, context)
    return HTMLResponse(content=html)


@app.get("/register", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
@app.get("/signup", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _signup():
    with open("./templates/html/signup_page.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    context = {
        "ENDPOINT": "/auth/signup",
    }
    html = render_html_template(html_content, context)
    return HTMLResponse(content=html)


@app.get("/logout", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _logout():
    with open("./templates/html/logout_page.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    context = {
        "ENDPOINT": "/auth/logout",
    }
    html = render_html_template(html_content, context)
    return HTMLResponse(content=html)


@app.get("/reset-password", tags=["PAGE"], include_in_schema=False, response_class=HTMLResponse)
def _reset_password():
    with open("./templates/html/reset_password_page.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    context = {
        "ENDPOINT": "/auth/password/reset",
    }
    html = render_html_template(html_content, context)
    return HTMLResponse(content=html)
