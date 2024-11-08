"""
This module contains the pydantic models for third-party accounts.

@file: ./app/templates/schemas/third_party_account.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from pydantic import BaseModel, field_validator

from app.core.oauth import oauth_clients_names

# pylint: disable=R0903


class ThirdPartyAccountBase(BaseModel):
    """
    Base model for third-party accounts.

    Attributes:
        acc_id (str): The account ID of the third-party account.
        provider (str): The provider of the third-party account.
        user_uuid (str): The UUID of the user associated with this account.
    """
    acc_id: str
    provider: str
    user_uuid: str

    @field_validator("provider")
    @classmethod
    def _validate_platform(cls, v: str) -> str:
        if v not in oauth_clients_names:
            raise ValueError("Invalid Provider")
        return v

    class Config:
        """ORM model configuration"""
        from_attributes = True
