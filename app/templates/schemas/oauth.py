from pydantic import BaseModel, Field, computed_field


class OAuth2TokenBase(BaseModel):
    """Base model for OAuth2 tokens."""
    name: str = Field(max_length=40)
    token_type: str = Field(max_length=40)
    access_token: str = Field(max_length=200)
    refresh_token: str = Field(max_length=200)
    expires_at: int = Field(default=0, ge=0,)
    user_uuid: str

    @computed_field
    def to_token(self):
        return dict(
            access_token=self.access_token,
            token_type=self.token_type,
            refresh_token=self.refresh_token,
            expires_at=self.expires_at,
        )
