from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings, logger
from app.core.db import get_db


@pytest.fixture(scope="module")
def client():
    """
    Provides a test client for making requests to the FastAPI app.
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def mock_db(mocker):
    """
    Mocks the database connection or operations if needed.
    """
    db_mock = mocker.patch('app.core.db.get_db')
    yield db_mock

# @pytest.fixture(scope="function")
# def mock_settings(request):
#     environment = request.param
#     with patch.object(settings, "ENVIRONMENT", environment):
#         yield settings
        
@pytest.fixture(scope="function")
def mock_settings(request):
    mock_data = request.param
    with patch.object(settings, "__setattr__"):
        for key, value in mock_data.items():
            setattr(settings, key, value)
        yield settings

@pytest.fixture
def mock_logger():
    with patch("app.core.config.logger") as mock_logger_obj:
        yield mock_logger_obj