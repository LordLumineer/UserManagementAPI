from unittest.mock import MagicMock, patch
import fakeredis
import pytest
from fastapi import FastAPI
from pytest_redis import factories
from starlette.testclient import TestClient

from app.core.middleware import GlobalRateLimiterMiddleware

FakeApp = FastAPI()

# Add middleware to the app
FakeApp.add_middleware(GlobalRateLimiterMiddleware, max_requests=5, window_seconds=60)


# Mock endpoints
@FakeApp.get("/public-endpoint")
def _public_endpoint():
    return {"message": "This is public"}

@FakeApp.get("/protected-endpoint")
async def _protected_endpoint():
    return {"message": "Protected endpoint"}

@pytest.fixture
def _client():
    return TestClient(FakeApp)


def test_cache_rate_limiter_middleware(_client):
    """Test GlobalRateLimiterMiddleware."""
    # Initialize redis_client in the state
    FakeApp.state.redis_client = None
    for _ in range(5):
        response = _client.get("/public-endpoint")
        assert response.status_code == 200
    response = _client.get("/public-endpoint")
    assert response.status_code == 429
    assert response.text == "Too Many Requests"

def test_redis_rate_limiter_middleware(_client):
    """Test GlobalRateLimiterMiddleware."""
    # Initialize redis_client in the state
    server = fakeredis.FakeServer()
    server.connected = True
    FakeApp.state.redis_client = fakeredis.FakeStrictRedis(server=server)
    # Not Limited
    for _ in range(5):
        response = _client.get("/public-endpoint")
        assert response.status_code == 200
    # Limited
    response = _client.get("/public-endpoint")
    assert response.status_code == 429
    assert response.text == "Too Many Requests"
    # Disconnected
    server.connected = False
    with patch("app.core.middleware.logger.error") as mock_logger:
        response = _client.get("/public-endpoint")
        mock_logger.assert_called_once_with("Redis connection lost. Falling back to in-memory cache.")
        assert FakeApp.state.redis_client is None
