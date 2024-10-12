import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.templates.models import User as User_Model
from app.templates.schemas.user import UserCreate, UserUpdate
from app.core.config import settings
from app.core.db import get_db
from app.core.security import hash_password
from app.core.object.user import (
    get_users, get_user, get_user_by_email, get_user_by_username,
    create_user, update_user, delete_user, link_file_to_user, delete_user_file
)

# -------- Mock Setup -------- #


@pytest.fixture
def mock_db_session():
    """Creates a mock DB session for testing."""
    return MagicMock(spec=Session)


@pytest.fixture
def sample_user():
    """Creates a sample user for testing."""
    return User_Model(
        uuid="test-uuid",
        username="testuser",
        email="testuser@example.com",
        hashed_password=hash_password("password"),
        permission="user",
        email_verified=True
    )

# -------- Testing get_users -------- #


def test_get_users(mock_db_session):
    # Arrange
    mock_db_session.query.return_value.offset.return_value.limit.return_value.all.return_value = []

    # Act
    result = get_users(mock_db_session, skip=0, limit=10)

    # Assert
    assert result == []
    mock_db_session.query.assert_called_once()

# -------- Testing get_user -------- #


def test_get_user(mock_db_session, sample_user):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = sample_user

    # Act
    result = get_user(mock_db_session, "test-uuid")

    # Assert
    assert result == sample_user
    mock_db_session.query.assert_called_once()


def test_get_user_not_found(mock_db_session):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = None

    # Act / Assert
    with pytest.raises(HTTPException) as exc_info:
        get_user(mock_db_session, "invalid-uuid")
    assert exc_info.value.status_code == 404


def test_get_user_username(mock_db_session, sample_user):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = sample_user

    # Act
    result = get_user_by_username(mock_db_session, "testuser")

    # Assert
    assert result == sample_user
    mock_db_session.query.assert_called_once()


def test_get_user_username_not_found(mock_db_session):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = None

    # Act / Assert
    with pytest.raises(HTTPException) as exc_info:
        get_user_by_username(mock_db_session, "invalid-username")
    assert exc_info.value.status_code == 404


def test_get_user_email(mock_db_session, sample_user):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = sample_user

    # Act
    result = get_user_by_email(mock_db_session, "testuser@example.com")

    # Assert
    assert result == sample_user
    mock_db_session.query.assert_called_once()


def test_get_user_email_not_found(mock_db_session):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = None

    # Act / Assert
    with pytest.raises(HTTPException) as exc_info:
        get_user_by_email(mock_db_session, "invalid-email")
    assert exc_info.value.status_code == 404

# -------- Testing create_user -------- #


async def test_create_user(mock_db_session):
    # Arrange
    user_data = UserCreate(
        username="testuser",
        email="testuser@example.com",
        password="password"
    )
    mock_db_session.commit.return_value = None

    # Act
    result = await create_user(mock_db_session, user_data)

    # Assert
    mock_db_session.add.assert_called_once()
    mock_db_session.commit.assert_called_once()
    assert result.username == user_data.username
    assert result.email == user_data.email


async def test_create_user_integrity_error(mock_db_session):
    # Arrange
    user_data = UserCreate(
        username="testuser",
        email="testuser@example.com",
        password="password"
    )
    mock_db_session.commit.side_effect = IntegrityError("mock", "mock", "mock")

    # Act / Assert
    with pytest.raises(HTTPException) as exc_info:
        await create_user(mock_db_session, user_data)
    assert exc_info.value.status_code == 400
    mock_db_session.rollback.assert_called_once()

# -------- Testing update_user -------- #


def test_update_user(mock_db_session, sample_user):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = sample_user
    update_data = UserUpdate(email="newemail@example.com")

    # Act
    result = update_user(mock_db_session, "test-uuid", update_data)

    # Assert
    assert result.email == update_data.email
    mock_db_session.commit.assert_called_once()


def test_update_user_integrity_error(mock_db_session, sample_user):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = sample_user
    mock_db_session.commit.side_effect = IntegrityError("mock", "mock", "mock")
    update_data = UserUpdate(email="newemail@example.com")

    # Act / Assert
    with pytest.raises(HTTPException) as exc_info:
        update_user(mock_db_session, "test-uuid", update_data)
    assert exc_info.value.status_code == 400
    mock_db_session.rollback.assert_called_once()

# -------- Testing delete_user -------- #


def test_delete_user(mock_db_session, sample_user):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = sample_user
    mock_db_session.commit.return_value = None

    # Act
    result = delete_user(mock_db_session, "test-uuid")

    # Assert
    assert result == True
    mock_db_session.commit.assert_called_once()


def test_delete_user_not_found(mock_db_session):
    # Arrange
    mock_db_session.query.return_value.filter.return_value.first.return_value = None

    # Act / Assert
    with pytest.raises(HTTPException) as exc_info:
        delete_user(mock_db_session, "invalid-uuid")
    assert exc_info.value.status_code == 404
