from unittest.mock import patch
import pytest
from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from starlette.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from app.core.middleware import FeatureFlagMiddleware, RedirectUriMiddleware

FakeApp = FastAPI()

# Add middleware to the app
FakeApp.add_middleware(FeatureFlagMiddleware)
FakeApp.add_middleware(RedirectUriMiddleware)
FakeApp.add_middleware(SessionMiddleware, secret_key="secret")

# Initialize redis_client in the state
FakeApp.state.redis_client = None

# Mock endpoints
@FakeApp.get("/public-endpoint")
def _public_endpoint():
    return {"message": "This is public"}

@FakeApp.get("/protected-endpoint")
async def _protected_endpoint():
    return {"message": "Protected endpoint"}

_protected_endpoint._feature_name = "PROTECTED_FEATURE"

@pytest.fixture
def _client():
    return TestClient(FakeApp)

# Mock data
MOCK_FEATURE_FLAGS = {
    "PROTECTED_FEATURE": True
}

# @pytest.fixture(autouse=True)
# def mock_redis_client():
#     with patch.object(FakeApp.state, "redis_client", None) as mock_redis:
#         yield mock_redis

def test_feature_flag_middleware(_client):
    """Test various scenarios for FeatureFlagMiddleware."""
    with patch("app.core.permissions.FEATURE_FLAGS", MOCK_FEATURE_FLAGS):
        with patch("app.core.permissions.can_view_feature") as mock_can_view_feature:
            with patch("app.db_objects.user.get_current_user") as mock_get_current_user:
                response = _client.get("/public-endpoint")
                assert response.status_code == 200
                assert response.json() == {"message": "This is public"}

                mock_can_view_feature.return_value = True
                mock_get_current_user.return_value = {"id": 1, "name": "Test User"}
                response = _client.get("/protected-endpoint", headers={"Authorization": "Bearer validtoken"})
                assert response.status_code == 200
                assert response.json() == {"message": "Protected endpoint"}

                mock_can_view_feature.return_value = False
                response = _client.get("/protected-endpoint", headers={"Authorization": "Bearer validtoken"})
                assert response.status_code == 403

                response = _client.get("/protected-endpoint")
                assert response.status_code == 403

                mock_get_current_user.side_effect = HTTPException(status_code=401, detail="Invalid token")
                response = _client.get("/protected-endpoint", headers={"Authorization": "Bearer invalidtoken"})
                assert response.status_code == 401

                mock_can_view_feature.return_value = True
                response = _client.get("/protected-endpoint")
                assert response.status_code == 200
                assert response.json() == {"message": "Protected endpoint"}

                mock_get_current_user.side_effect = HTTPException(status_code=401, detail="Token expired")
                response = _client.get("/protected-endpoint", headers={"Authorization": "Bearer expiredtoken"})
                assert response.status_code == 200
                assert response.json() == {"message": "Protected endpoint"}

def test_redirect_uri_middleware(_client):
    """Test RedirectUriMiddleware."""
    response = _client.get("/public-endpoint?redirect_uri=http://example.com")
    assert response.status_code == 200
    assert response.json() == {"message": "This is public"}
