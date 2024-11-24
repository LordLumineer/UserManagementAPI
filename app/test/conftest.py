"""
This module contains fixtures and test utilities for the application.

It includes a fixture to provide a test client for the FastAPI app and a fixture to mock
the database connection. Additionally, it provides a fixture to temporarily override
application settings for testing purposes.
"""
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings  # , logger
# from app.core.db import get_db


@pytest.fixture(scope="module")
def client():
    """Provides a test client for making requests to the FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client

@pytest.fixture
def mock_db(mocker):
    """Mocks the database connection or operations if needed."""
    db_mock = mocker.patch('app.core.db.get_db')
    yield db_mock


@pytest.fixture(scope="function")
def mock_settings(request):
    """Allows to temporarily override settings for a test."""
    mock_data = request.param
    with patch.object(settings, "__setattr__"):
        for key, value in mock_data.items():
            setattr(settings, key, value)
        yield settings


@pytest.fixture
def mock_logger():
    """Patches the logger object to allow capturing log messages in tests."""
    with patch("app.core.config.logger") as mock_logger_obj:
        yield mock_logger_obj
