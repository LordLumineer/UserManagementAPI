"""Tests for the FeatureFlagMiddleware."""
from unittest.mock import patch
import pytest
from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from starlette.testclient import TestClient

from app.core.middleware import FeatureFlagMiddleware
from app.core.permissions import FEATURE_FLAGS, can_view_feature  # pylint: disable=W0611

# pylint: disable=W0212

FakeApp = FastAPI()

# Add middleware to the app
FakeApp.add_middleware(FeatureFlagMiddleware)

# Mock endpoints


@FakeApp.get("/public-endpoint")
async def _public_endpoint():
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


def test_feature_flag_middleware(_client):
    """Test various scenarios for FeatureFlagMiddleware."""
    # Mock feature flags
    with patch("app.core.permissions.FEATURE_FLAGS", MOCK_FEATURE_FLAGS):
        with patch("app.core.permissions.can_view_feature") as mock_can_view_feature:
            with patch("app.db_objects.user.get_current_user") as mock_get_current_user:
                # Test 1: Public endpoint, no feature flags
                response = _client.get("/public-endpoint")
                assert response.status_code == 200
                assert response.json() == {"message": "This is public"}

                # Test 2: Protected endpoint, feature flag enabled, user authorized
                mock_can_view_feature.return_value = True
                mock_get_current_user.return_value = {
                    "id": 1, "name": "Test User"}
                response = _client.get(
                    "/protected-endpoint", headers={"Authorization": "Bearer validtoken"})
                assert response.status_code == 200
                assert response.json() == {"message": "Protected endpoint"}

                # Test 3: Protected endpoint, feature flag enabled, user unauthorized
                mock_can_view_feature.return_value = False
                response = _client.get(
                    "/protected-endpoint", headers={"Authorization": "Bearer validtoken"})
                assert response.status_code == 403

                # {"error": "Access to feature 'protected_endpoint:PROTECTED_FEATURE' is denied."}

                # Test 4: Protected endpoint, no authorization header
                mock_can_view_feature.return_value = False
                response = _client.get("/protected-endpoint")
                assert response.status_code == 403

                # Test 5: Protected endpoint, invalid token
                mock_can_view_feature.return_value = False
                mock_get_current_user.side_effect = HTTPException(
                    status_code=401, detail="Invalid token")
                response = _client.get(
                    "/protected-endpoint", headers={"Authorization": "Bearer invalidtoken"})
                assert response.status_code == 401

                # Test 6: Protected endpoint, feature flag missing
                mock_can_view_feature.return_value = True
                response = _client.get("/protected-endpoint")
                assert response.status_code == 200
                assert response.json() == {"message": "Protected endpoint"}

                # Test 7: Protected endpoint, Token expired
                mock_can_view_feature.return_value = True
                mock_get_current_user.side_effect = HTTPException(
                    status_code=401, detail="Token expired")
                response = _client.get(
                    "/protected-endpoint", headers={"Authorization": "Bearer expiredtoken"})
                assert response.status_code == 200
                assert response.json() == {"message": "Protected endpoint"}
