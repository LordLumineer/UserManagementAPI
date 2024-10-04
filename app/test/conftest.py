"""
Test fixtures and utilities for the Ko-fi donation API.

@file: ./app/test/conftest.py
@date: 2024-09-27
@author: Lord Lumineer (lordlumineer@gmail.com)
"""
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
import pytest

from app.core.config import Settings
from app.main import app
# from app.core.db import get_db
# from app.core import models


# Mock settings


@pytest.fixture
def client():
    """
    Fixture to create a TestClient for the FastAPI app.

    Returns:
        TestClient: A TestClient for the FastAPI app.
    """
    return TestClient(app)


@pytest.fixture
def mock_db_session():
    """
    Fixture to mock the database session dependency.

    Yields a mock Session object from sqlalchemy.orm, which is returned by get_db().
    The mock is configured to be used as a context manager, so when the test needs
    to access the database, the mock session is returned as an iterator.
    """
    with patch("app.core.db.SessionLocal") as mock:
        mock.return_value = MagicMock()
        yield mock.return_value
