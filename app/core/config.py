"""This module contains the settings for the application. It also sets up the logger."""
import asyncio
import sys
import os
from typing import Literal, Self
from fastapi.templating import Jinja2Templates
from pydantic import Field, PostgresDsn, model_validator, computed_field
# from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from pytz import utc
from sqlalchemy import URL
from loguru import logger as loguru_logger

logger = loguru_logger

app_root_dir = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."))


class _Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.path.normpath(os.path.join(app_root_dir, "app", ".env")),
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore"
    )

    PROJECT_NAME: str = Field(default="Project Name")
    BASE_URL: str = Field(default="http://localhost:8000")
    API_STR: str = Field(default="/api")
    FRONTEND_URL: str | None = None

    LOG_LEVEL: Literal['TRACE', 'DEBUG', 'INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL'] = Field(
        default='INFO'
    )
    LOG_FILE_ENABLED: bool = Field(default=False)
    LOG_FILE_LEVEL: Literal['TRACE', 'DEBUG', 'INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL'] = Field(
        default='WARNING'
    )
    LOG_FILE_ROTATION: int | str = Field(default=24)
    LOG_FILE_RETENTION: int | str = Field(default=30)

    # NOTE: Do not change JWT_ALGORITHM, this can cause issues
    JWT_ALGORITHM: str = Field(default="HS256")
    JWT_SECRET_KEY: str = Field(default="changethis")
    JWT_EXP: int = Field(default=30)

    OTP_LENGTH: int = Field(default=6)
    OTP_AUTHENTICATOR_INTERVAL: int = Field(default=30)
    OTP_EMAIL_INTERVAL: int = Field(default=600)  # seconds

    ENVIRONMENT: Literal["local", "production"] = Field(
        default="local")  # "local" # .env

    APP_ROOT_DIR: str = app_root_dir

    FEATURE_FLAGS_ENABLED: bool = Field(default=False)
    FEATURE_FLAGS_FILE: str = Field(default="feature_flags.json")

    PROTECTED_INTERACTIVE_DOCS: bool = Field(default=True)

    DATABASE_URI: str = f"sqlite+aiosqlite:///{os.path.normpath(
        os.path.join(app_root_dir, "data", "Project.db"))}"

    POSTGRES_SERVER: str | None = None
    POSTGRES_PORT: int | None = None
    POSTGRES_USER: str | None = None
    POSTGRES_PASSWORD: str | None = None
    POSTGRES_DB: str | None = None

    # NOTE: Do not reduce the amount too much, this can cause issues
    RATE_LIMITER_ENABLED: bool = Field(default=True)
    RATE_LIMITER_MAX_REQUESTS: int = Field(default=300)
    RATE_LIMITER_WINDOW_SECONDS: int = Field(default=900)
    REDIS_URL: str | None = None

    CONTACT_EMAIL: str | None = None  # "<no-contact-email>@<domain>"
    EMAIL_METHOD: Literal["none", "smtp", "mj"] = Field(default="none")

    MJ_APIKEY_PUBLIC: str | None = None
    MJ_APIKEY_PRIVATE: str | None = None
    MJ_SENDER_EMAIL: str | None = None

    SMTP_TLS: bool = True
    SMTP_PORT: int = 587
    SMTP_HOST: str | None = None
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_SENDER_EMAIL: str | None = None

    API_CLIENT_ID_GOOGLE: str | None = None
    API_CLIENT_SECRET_GOOGLE: str | None = None
    API_CLIENT_ID_TWITCH: str | None = None
    API_CLIENT_SECRET_TWITCH: str | None = None
    API_CLIENT_ID_GITHUB: str | None = None
    API_CLIENT_SECRET_GITHUB: str | None = None
    API_CLIENT_ID_DISCORD: str | None = None
    API_CLIENT_SECRET_DISCORD: str | None = None
    API_CLIENT_ID_TWITTER: str | None = None
    API_CLIENT_SECRET_TWITTER: str | None = None
    # API_CLIENT_ID_REDDIT: str | None = None
    # API_CLIENT_SECRET_REDDIT: str | None = None
    # API_CLIENT_ID_MICROSOFT: str | None = None
    # API_CLIENT_SECRET_MICROSOFT: str | None = None

    @computed_field
    def MACHINE(self) -> dict:  # pylint: disable=C0103
        """The machine the application is running on."""
        from app.core.utils import get_machine_info  # pylint: disable=C0415
        return asyncio.run(get_machine_info())

    @computed_field
    def REPOSITORY(self) -> dict:  # pylint: disable=C0103
        """Retrieves the repository information and the latest commit details."""
        from app.core.utils import get_latest_commit_info, get_repository_info  # pylint: disable=C0415
        commit_info = get_latest_commit_info()
        repo_info = get_repository_info()
        repository = {}
        if commit_info:
            repository["latest_commit"] = commit_info
        if repo_info:
            repository["repository"] = repo_info
        return repository

    @computed_field
    def SQLALCHEMY_DATABASE_URI(self) -> PostgresDsn | None:  # pylint: disable=C0103
        """
        If all the POSTGRES_* variables are set, return a PostgresDsn string with the
        appropriate values. Otherwise, return the DATABASE_URI string.
        """
        if not (self.POSTGRES_SERVER and self.POSTGRES_USER and self.POSTGRES_PASSWORD and self.POSTGRES_DB):
            return self.DATABASE_URI
        return URL.create(
            "postgresql+psycopg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB,
        )
        # return MultiHostUrl.build(
        #         scheme="postgresql",
        #         username=self.POSTGRES_USER,
        #         password=self.POSTGRES_PASSWORD,
        #         host=self.POSTGRES_SERVER,
        #         port=self.POSTGRES_PORT,
        #         path=self.POSTGRES_DB,
        #     )

    @computed_field
    def FEATURE_FLAGS_PATH(self) -> str:  # pylint: disable=C0103
        """The path to the feature flags file."""
        return os.path.normpath(os.path.join(
            app_root_dir, "data", self.FEATURE_FLAGS_FILE
        ))

    def _check_default_secret(self, var_name: str, value: str | None) -> None:
        if value == "changethis":
            message = (
                f'The value of {var_name} is "changethis", '
                "for security, please change it, at least for deployments."
            )
            if self.ENVIRONMENT == "local":
                # warnings.warn(message, stacklevel=1)
                logger.warning(message)
            else:
                raise ValueError(message)

    @model_validator(mode="after")
    def _enforce_non_default_secrets(self) -> Self:
        self._check_default_secret("JWT_SECRET_KEY", self.JWT_SECRET_KEY)
        return self

    @model_validator(mode="after")
    def _verify_email_settings(self) -> Self:
        if self.EMAIL_METHOD == "smtp":
            if (
                self.SMTP_PORT is None or
                self.SMTP_HOST is None or
                self.SMTP_USER is None or
                self.SMTP_PASSWORD is None or
                self.SMTP_SENDER_EMAIL is None
            ):
                logger.critical(
                    "SMTP Email Settings are set. EMAIL_METHOD will be set to 'none'")
                self.EMAIL_METHOD = "none"  # pylint: disable=C0103
                return self
            logger.info(
                "SMTP Email Settings are set.")
            return self
        if self.EMAIL_METHOD == "mj":
            if (
                self.MJ_APIKEY_PUBLIC is None or
                self.MJ_APIKEY_PRIVATE is None or
                self.MJ_SENDER_EMAIL is None
            ):
                logger.critical(
                    "MailJet Email Settings are set. EMAIL_METHOD will be set to 'none'")
                self.EMAIL_METHOD = "none"  # pylint: disable=C0103
                return self
            logger.info(
                "MailJet Email Settings are set."
            )
            return self
        logger.warning("EMAIL_METHOD will is set to 'none'.")
        self.EMAIL_METHOD = "none"  # pylint: disable=C0103
        return self

    @model_validator(mode="after")
    def _define_frontend_url(self) -> Self:
        self.FRONTEND_URL = self.FRONTEND_URL or self.BASE_URL  # pylint: disable=C0103
        return self

    @model_validator(mode="after")
    def _validate_database_url(self) -> Self:
        if self.DATABASE_URI is not None:
            protocol = self.DATABASE_URI.split('://')[0]
            match protocol:
                case str(proto) if "postgresql" in proto:
                    self.DATABASE_URI = "postgresql+psycopg://" + self.DATABASE_URI.split('://', maxsplit=1)[1]  # pylint: disable=C0103
                case str(proto) if "sqlite" in proto:
                    self.DATABASE_URI = "sqlite+aiosqlite://" + self.DATABASE_URI.split('://', maxsplit=1)[1]  # pylint: disable=C0103
                case _:
                    # Not a valid or yet supported database URI
                    self.DATABASE_URI = None
        return self


settings = _Settings()

templates = Jinja2Templates(directory=os.path.join(
    app_root_dir, "app", "templates", "html"))


def _fix_timezone(record):
    utc_time = record["time"].astimezone(utc)
    record["time"] = utc_time


logger.configure(patcher=_fix_timezone)

logger.remove(0)
logger.add(
    sys.stderr,
    level=settings.LOG_LEVEL,
    colorize=True,
    format=(
        "<green>{time:YYYY/MM/DD HH:mm:ss zz}</green> | "
        "<level>{level:<8}</level> | "
        "<cyan>{module}:{function}:{line}</cyan> - "
        "<level>{message}</level>"
    ),
    enqueue=True,
    diagnose=True,
)

if settings.LOG_FILE_ENABLED:
    logger.add(
        os.path.normpath(os.path.join(
            app_root_dir, "data", "logs",
            "{time:YYYY_MM_DD_HH_mm_ss_ZZ!UTC}.log")),
        level=settings.LOG_FILE_LEVEL,
        rotation=f"{settings.LOG_FILE_ROTATION} hours" if isinstance(
            settings.LOG_FILE_ROTATION, int) else settings.LOG_FILE_ROTATION,
        retention=f"{settings.LOG_FILE_RETENTION} days" if isinstance(
            settings.LOG_FILE_RETENTION, int) else settings.LOG_FILE_RETENTION,
        compression="zip",
        delay=True,
        enqueue=True,
    )


# NOTE: Uncomment to use the app logger (loguru) for the FastAPI one (uvicorn)
# STILL BUGGED

# class LoguruHandler(logging.Handler):
#     def emit(self, record):
#         logger.opt(depth=6, exception=record.exc_info).log(
#             record.levelname, record.getMessage())


# for _logger in logging.root.manager.loggerDict.values():  # pylint: disable=E1101
#     if isinstance(_logger, logging.Logger):
#         if "uvicorn" in _logger.name:
#             _logger.disabled = False
#             for handler in _logger.handlers[:]:
#                 _logger.removeHandler(handler)
#             loguru_handler = LoguruHandler()
#             _logger.addHandler(loguru_handler)
#             _logger.setLevel(settings.LOG_LEVEL)
