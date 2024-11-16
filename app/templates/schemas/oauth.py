"""
This module defines the base model for OAuth2 tokens, supporting both OAuth1 and OAuth2 token structures.

@file: ./app/templates/schemas/oauth.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""

from typing import Literal, Self
from pydantic import BaseModel, Field, model_validator

# pylint: disable=R0903


class OAuthTokenBase(BaseModel):
    """Base model for OAuth2 tokens."""
    oauth_version: Literal["1", "2"] = Field(default="2", max_length=1)
    provider: str = Field(max_length=40)
    # OAuth1
    oauth_token: str | None = Field(default=None)
    oauth_token_secret: str | None = Field(default=None)
    # OAuth2
    token_type: str | None = Field(default=None, max_length=40)
    access_token: str | None = Field(default=None)
    refresh_token: str | None = Field(default=None)
    expires_at: int | None = Field(default=0, ge=0)

    user_uuid: str

    @model_validator(mode='after')
    def _ensure_token_version_data(self) -> Self:
        if self.oauth_version == "1" and (
            self.oauth_token is None or
            self.oauth_token_secret is None
        ):
            raise ValueError("Missing OAuth1 token values")
        if self.oauth_version == "2" and (
            self.access_token is None or
            self.token_type is None or
            self.refresh_token is None or
            self.expires_at is None
        ):
            raise ValueError("Missing OAuth2 token values")
        return self

    def to_token(self) -> dict:
        """Returns the OAuth token as a dictionary.

        The keys of the dictionary will depend on the oauth_version of the token.
        For OAuth1 tokens, the keys will be "oauth_token" and "oauth_token_secret".
        For OAuth2 tokens, the keys will be "access_token", "token_type", "refresh_token", and "expires_at".
        """
        if self.oauth_version == "1":
            return {
                "oauth_token": self.oauth_token,
                "oauth_token_secret": self.oauth_token_secret,
            }
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
        }

    class Config:
        """ORM model configuration"""
        from_attributes = True
