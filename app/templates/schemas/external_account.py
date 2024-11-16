"""
This module contains the pydantic models for External accounts.

@file: ./app/templates/schemas/external_account.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from pydantic import BaseModel, field_validator

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

    class Config:
        """ORM model configuration"""
        from_attributes = True
