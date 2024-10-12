import logging
import warnings
from typing import Literal, Self
from pydantic import Field, PostgresDsn, model_validator, computed_field
from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", env_ignore_empty=True, extra="ignore"
    )

    PROJECT_NAME: str = Field(default="OpenShelf")
    BASE_URL: str = Field(default="http://127.0.0.1:8000")  # .env
    API_STR: str = Field(default="/api")
    FRONTEND_URL: str = Field(default="http://127.0.0.1:8000")

    JWT_ALGORITHM: str = Field(default="HS256")
    JWT_SECRET_KEY: str = Field(default="changethis")
    JWT_EXP: int = Field(default=30)

    OTP_LENGTH: int = Field(default=6)
    OTP_AUTHENTICATOR_INTERVAL: int = Field(default=30)
    OTP_EMAIL_INTERVAL: int = Field(default=600) # seconds

    ENVIRONMENT: Literal["local", "production"] = Field(
        default="local")  # "local" # .env

    DATABASE_URI: str = "sqlite:///../data/OpenShelf.db"

    POSTGRES_SERVER: str | None = None
    POSTGRES_PORT: int | None = None
    POSTGRES_USER: str | None = None
    POSTGRES_PASSWORD: str | None = None
    POSTGRES_DB: str | None = None
    
    CONTACT_EMAIL: str | None = None
    EMAIL_METHOD: Literal["none","smtp", "mj"] = Field(default="none")
    
    MJ_APIKEY_PUBLIC: str | None = None
    MJ_APIKEY_PRIVATE: str | None = None
    MJ_SENDER_EMAIL: str | None = None
    
    SMTP_TLS: bool = True
    SMTP_PORT: int = 587
    SMTP_HOST: str | None = None
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_SENDER_EMAIL: str | None = None
    
    @computed_field
    def SQLALCHEMY_DATABASE_URI(self) -> PostgresDsn | None:
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
        """
        Check if the value of a secret variable is the default and warn/error accordingly.

        Args:
            var_name (str): The name of the secret variable.
            value (str | None): The value of the secret variable.

        Raises:
            ValueError: 
                If the value of the secret variable is the default and the environment is not local.
        """
        if value == "changethis":
            message = (
                f'The value of {var_name} is "changethis", '
                "for security, please change it, at least for deployments."
            )
            if self.ENVIRONMENT == "local":
                warnings.warn(message, stacklevel=1)
            else:
                raise ValueError(message)

    @model_validator(mode="after")
    def _enforce_non_default_secrets(self) -> Self:
        """
        Enforce that the default secrets are not used in non-local environments.

        This model validator function will check if the default secrets are used and
        warn/error accordingly. This is to ensure that the API is not deployed with
        the default secrets.
        """
        self._check_default_secret("JWT_SECRET_KEY", self.JWT_SECRET_KEY)

        return self


settings = Settings()  # type: ignore

logger = logging.getLogger("uvicorn")
if not logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s:     %(message)s",
        handlers=[logging.StreamHandler()]  # Output to stdout
    )
    logger = logging.getLogger(__name__)
