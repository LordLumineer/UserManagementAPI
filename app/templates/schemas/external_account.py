"""This module contains the pydantic models for External accounts."""
from pydantic import BaseModel, ConfigDict, field_validator

from app.core.oauth import oauth_clients_names

# pylint: disable=R0903


class ExternalAccountBase(BaseModel):
    """
    Base model for External accounts.

    Attributes:
        external_account_id (str): The account ID of the third-party account.
        provider (str): The provider of the third-party account.
        user_uuid (str): The UUID of the user associated with this account.
    """
    external_account_id: str
    provider: str
    user_uuid: str

    username: str | None
    display_name: str | None
    email: str | None
    picture_url: str | None

    @field_validator("provider")
    @classmethod
    def _validate_platform(cls, v: str) -> str:
        if v not in oauth_clients_names:
            raise ValueError("Invalid Provider")
        return v

    model_config = ConfigDict(from_attributes=True)
