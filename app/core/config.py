"""This module contains the settings for the application. It also sets up the logger."""
import logging
import os
import time
from typing import Literal, Self
from colorama import Fore
from pydantic import Field, PostgresDsn, model_validator, computed_field
# from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL
from uvicorn.logging import ColourizedFormatter

logger = logging.getLogger("uvicorn.access")
for handler in logger.handlers:
    handler.setFormatter(ColourizedFormatter(
        fmt=(
            f"{Fore.LIGHTBLACK_EX}%(asctime)s GMT | {Fore.RESET}"
            f"%(levelprefix)-8s %(message)s"
        ),
        datefmt="%Y/%m/%d %H:%M:%S",
        style="%",
        use_colors=True
    ))
    handler.formatter.converter = time.gmtime

app_root_dir = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."))

class _Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", env_ignore_empty=True, extra="ignore"
    )

    PROJECT_NAME: str = Field(default="Project Name")
    # Field(default="http://127.0.0.1:8000")  # .env
    BASE_URL: str = Field(default="http://localhost")
    API_STR: str = Field(default="/api")
    # Field(default="http://127.0.0.1:8000")
    FRONTEND_URL: str = Field(default="http://localhost")

    LOG_LEVEL: Literal["debug", "info", "warning", "error", "critical"] = Field(
        default="info"
    )

    JWT_ALGORITHM: str = Field(default="HS256")
    JWT_SECRET_KEY: str = Field(default="changethis")
    JWT_EXP: int = Field(default=30)

    OTP_LENGTH: int = Field(default=6)
    OTP_AUTHENTICATOR_INTERVAL: int = Field(default=30)
    OTP_EMAIL_INTERVAL: int = Field(default=600)  # seconds

    ENVIRONMENT: Literal["local", "production"] = Field(
        default="local")  # "local" # .env

    APP_ROOT_DIR: str = app_root_dir

    FEATURE_FLAGS_FILE: str = Field(
        default=os.path.normpath(os.path.join(
            app_root_dir, "data", "feature_flags.json"
        )),
        # default="../data/feature_flags.json"
    )

    DATABASE_URI: str = f"sqlite:///{os.path.normpath(
        os.path.join(app_root_dir, "data", "Project.db"))}"

    POSTGRES_SERVER: str | None = None
    POSTGRES_PORT: int | None = None
    POSTGRES_USER: str | None = None
    POSTGRES_PASSWORD: str | None = None
    POSTGRES_DB: str | None = None

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
        return get_machine_info()

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
            "postgresql+pg8000",
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
        logger.warning(
            "EMAIL_METHOD will is set to 'none'")
        self.EMAIL_METHOD = "none"  # pylint: disable=C0103
        return self


settings = _Settings()

logger.setLevel(str(settings.LOG_LEVEL).upper())
