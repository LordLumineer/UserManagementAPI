from pydantic import BaseModel, field_validator

from app.core.oauth import oauth_clients_names


class ThirdPartyAccountBase(BaseModel):
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