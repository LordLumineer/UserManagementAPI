"""
Tests for the main entrypoint of the application

This module contains tests for the main entrypoint of the application, which is
responsible for creating the FastAPI application and setting up the routes and
middleware.
"""
from unittest.mock import patch
import pytest
from fastapi.responses import FileResponse
from fastapi import status

from app.main import _favicon


@pytest.mark.parametrize("endpoint", [
    "/ping",
    "/machine",
    "/repository",
    "/version"
])
def test_debug_and_info_endpoint(endpoint, client):
    """Test the debug and info endpoints."""

    response = client.get(endpoint)
    assert response.status_code == status.HTTP_200_OK
    match endpoint:
        case "/ping":
            assert response.text == '"pong"'
        case "/machine":
            assert set(["platform", "system", "version", "release", "architecture", "processor",
                        "cpu_count", "python_version", "is_docker", "uname"]) & set(response.json())
        case "/repository":
            assert "latest_commit" in response.json()
        case "/version":
            assert "FastAPI_Version" in response.json()
            assert "Project_Version" in response.json()
            assert "Python_Version" in response.json()


@pytest.mark.parametrize(
    "favicon_exists, logo_exists, expected_response_type",
    [
        (True, False, FileResponse),   # Case 1: favicon.ico exists
        (False, True, FileResponse),   # Case 2: logo.png exists
        (False, False, str),           # Case 3: Neither exists, generate initials
    ],
)
@patch("app.main.os.path.exists")
@patch("app.main.generate_profile_picture")
# Identity function for simplicity
def test_favicon_cases(mock_generate_pic, mock_exists,
                       favicon_exists, logo_exists, expected_response_type):
    """Test favicon endpoint under different file existence scenarios."""

    # Mock os.path.exists behavior based on input parameters
    mock_exists.side_effect = lambda path: (
        "favicon.ico" in path if favicon_exists else "logo.png" in path if logo_exists else False
    )

    # Mock profile picture generation return value for case 3
    mock_generate_pic.return_value = "mocked_profile_pic.png"
    with patch("app.main.app_path", side_effect=lambda x: x):
        response = _favicon()

    if expected_response_type is FileResponse:
        assert isinstance(response, FileResponse)
        assert response.path.endswith(
            "favicon.ico" if favicon_exists else "logo.png")
    else:
        # For Case 3, check that generate_profile_picture was called and response matches the mock
        mock_generate_pic.assert_called_once()
        assert response == "mocked_profile_pic.png"
