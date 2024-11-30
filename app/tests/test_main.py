
import os
from unittest.mock import AsyncMock, patch

from fastapi.responses import FileResponse
import pytest
# from httpx import AsyncClient
from fastapi import status
from sqlalchemy.exc import IntegrityError

from app.main import _favicon
# from app.main import app
# from app.core.config import settings


# @pytest.fixture
# async def client():
#     async with AsyncClient(app=app, base_url="http://test") as client:
#         yield client

# from app.main import (
#     app,
#     lifespan
# )


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "/ping",
    "/machine",
    "/repository",
    "/version"
])
async def test_debug_and_info_endpoint(endpoint, client):
    response = client.get(endpoint)
    assert response.status_code == status.HTTP_200_OK
    match endpoint:
        case "/ping":
            assert response.text == '"pong"'
        case "machine":
            assert ("platform", "system", "version", "release", "architecture", "processor",
                    "cpu_count", "python_version", "is_docker", "uname") in response.json()
        case "repository":
            assert "latest_commit" in response.json()
        case "version":
            assert "FastAPI_Version" in response.json()
            assert "Project_Version" in response.json()
            assert "Python_Version" in response.json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "favicon_exists, logo_exists, expected_response_type",
    [
        (True, False, FileResponse),   # Case 1: favicon.ico exists
        (False, True, FileResponse),   # Case 2: logo.png exists
        (False, False, str),           # Case 3: Neither exists, generate initials
    ],
)
@patch("app.main.os.path.exists")
@patch("app.main.generate_profile_picture", new_callable=AsyncMock)
# Identity function for simplicity
@patch("app.main.app_path", side_effect=lambda x: x)
async def test_favicon_cases(mock_app_path, mock_generate_pic, mock_exists, favicon_exists, logo_exists, expected_response_type, client):
    """Test favicon endpoint under different file existence scenarios."""

    # Mock os.path.exists behavior based on input parameters
    mock_exists.side_effect = lambda path: (
        "favicon.ico" in path if favicon_exists else "logo.png" in path if logo_exists else False
    )

    # Mock profile picture generation return value for case 3
    mock_generate_pic.return_value = "mocked_profile_pic.png"

    response = await _favicon()

    if expected_response_type is FileResponse:
        assert isinstance(response, FileResponse)
        assert response.path.endswith(
            "favicon.ico" if favicon_exists else "logo.png")
    else:
        # For Case 3, check that generate_profile_picture was called and response matches the mock
        mock_generate_pic.assert_called_once()
        assert response == "mocked_profile_pic.png"


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "/",
    "/terms",
    "/privacy",
    "/support",
])
async def test_placeholders_page(endpoint, client):
    """Test the /<placeholders> endpoint rendering."""
    response = client.get(endpoint)
    # assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "404 - Page Not Found" in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", [
    "/login",
    "/signin",
    "/otp",
    "/register",
    "/signup",
    "/logout",
    "/reset-password",
    "/forgot-password/request-form",
    "/forgot-password/reset-form",
])
async def test_backups_page(endpoint, client):
    """Test the /login endpoint rendering."""
    response = client.get(endpoint)
    assert response.status_code == status.HTTP_200_OK
    assert "/auth/" in response.text
