"""This module contains the settings for the application. It also sets up the logger."""
import logging
import os
import platform
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
    API_CLIENT_ID_TWITTER: str | None = None
    API_CLIENT_SECRET_TWITTER: str | None = None
    # API_CLIENT_ID_REDDIT: str | None = None
    # API_CLIENT_SECRET_REDDIT: str | None = None
    # API_CLIENT_ID_MICROSOFT: str | None = None
    # API_CLIENT_SECRET_MICROSOFT: str | None = None

    def _detect_docker(self):
        if os.path.exists('/.dockerenv'):
            return True
        try:
            with open('/proc/self/cgroup', 'r', encoding='utf-8') as f:
                if 'docker' in f.read():
                    return True
        except FileNotFoundError:
            pass
        return False

    @computed_field
    def MACHINE(self) -> dict:  # pylint: disable=C0103
        """The machine the application is running on."""
        machine = {
            "platform": platform.platform(),
            "system": platform.system(),
            "version": platform.version(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "python_version": platform.python_version(),
            "is_docker": self._detect_docker()
        }
        match machine["system"]:
            # case "Java":
            #     machine["details"] = {
            #         "java_ver": platform.java_ver()
            #     }
            case "Windows":
                machine["details"] = {
                    "win32_ver": platform.win32_ver(),
                    "win32_is_iot": platform.win32_is_iot(),
                    "win32_edition": platform.win32_edition(),
                }
            case "Linux":
                machine["details"] = {
                    "freedesktop_os_release": platform.freedesktop_os_release()
                }
            case "Darwin":
                machine["details"] = {
                    "mac_ver": platform.mac_ver()
                }
            case "iOS" | "iPadOS":
                machine["details"] = {
                    "ios_ver": platform.ios_ver()  # pylint: disable=E1101
                }
            case "Android":
                machine["details"] = {
                    "android_ver": platform.android_ver()  # pylint: disable=E1101
                }
            case _:
                machine["details"] = {
                    "platform": "Unknown OS",
                    "libc_ver": platform.libc_ver()
                }
        return machine

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
