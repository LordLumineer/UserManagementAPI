from typing import Literal, Self
from pydantic import BaseModel, Field, model_validator


class OAuthTokenBase(BaseModel):
    """Base model for OAuth2 tokens."""
    oauth_version: Literal["1", "2"] = Field(default="2", max_length=1)
    name: str = Field(max_length=40)
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
        if self.oauth_version == "1":
            return dict(
                oauth_token=self.oauth_token,
                oauth_token_secret=self.oauth_token_secret,
            )
        return dict(
            access_token=self.access_token,
            token_type=self.token_type,
            refresh_token=self.refresh_token,
            expires_at=self.expires_at,
        )

    class Config:
        """ORM model configuration"""
        from_attributes = True
