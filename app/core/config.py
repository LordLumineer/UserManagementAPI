"""
This module contains the settings for the application. It also sets up the logger.

@file: ./app/core/config.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
import logging
from typing import Literal, Self
from pydantic import Field, PostgresDsn, model_validator, computed_field
from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


logger = logging.getLogger("uvicorn")
if not logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s:     %(message)s",
        handlers=[logging.StreamHandler()]  # Output to stdout
    )
    logger = logging.getLogger(__name__)


class _Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", env_ignore_empty=True, extra="ignore"
    )

    PROJECT_NAME: str = Field(default="OpenShelf")
    BASE_URL: str = Field(default="http://127.0.0.1:8000")  # .env
    API_STR: str = Field(default="/api")
    FRONTEND_URL: str = Field(default="http://127.0.0.1:8000")

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

    DATABASE_URI: str = "sqlite:///../data/OpenShelf.db"

    POSTGRES_SERVER: str | None = None
    POSTGRES_PORT: int | None = None
    POSTGRES_USER: str | None = None
    POSTGRES_PASSWORD: str | None = None
    POSTGRES_DB: str | None = None

    CONTACT_EMAIL: str | None = None
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

    @computed_field
    def SQLALCHEMY_DATABASE_URI(self) -> PostgresDsn | None:  # pylint: disable=C0103
        """
        If all the POSTGRES_* variables are set, return a PostgresDsn string with the
        appropriate values. Otherwise, return the DATABASE_URI string.
        """
        if not (self.POSTGRES_SERVER and self.POSTGRES_USER and self.POSTGRES_PASSWORD and self.POSTGRES_DB):
            return self.DATABASE_URI
        return MultiHostUrl.build(
            scheme="postgresql",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        )

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
