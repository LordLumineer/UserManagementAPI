"""
Tests for the security module.

This module contains tests for the security-related functions in the core package.
"""
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, timezone
import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from authlib.jose.errors import DecodeError
import pyotp
from pydantic import ValidationError

from app.core.config import settings
from app.core.utils import generate_random_letters
from app.core.security import (
    TokenData,
    authenticate_user,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
    generate_otp,
    validate_otp
)

pytest_plugins = ('pytest_asyncio',)


@pytest.mark.parametrize("purpose, data, should_raise", [
    ("login", {"uuid": "123", "roles": ["admin"]}, False),
    ("login", {"uuid": "123"}, True),  # Missing roles
    ("reset-password", {"uuid": "456", "username": "test_user"}, False),
    ("reset-password", {"uuid": "456"}, True),  # Missing username
    ("email-verification", {"uuid": "789",
     "email": "test@example.com"}, False),
    ("email-verification", {"uuid": "789"}, True),  # Missing email
    ("OTP", {"uuid": "101112"}, False),  # No extra data needed
    ("unknown", {"uuid": "131415"}, True),  # Invalid purpose
])
def test_token_data_validation(purpose, data, should_raise):
    """Test TokenData validation with various inputs."""
    data["purpose"] = purpose
    if should_raise:
        with pytest.raises((ValueError, ValidationError)):
            TokenData(**data)
    else:
        assert TokenData(**data)


@pytest.mark.parametrize("password, has_error", [
    ("password123", False),
    ("", False),
    ("p@$$w0rd!", False),
    ("pässwörd", False),
    ("special@char", True),
])
def test_hash_and_verify_password(password, has_error):
    """Test password hashing and verification with various inputs."""
    if has_error:
        with pytest.raises(HTTPException):
            with patch("bcrypt.hashpw", side_effect=UnicodeEncodeError(
                "utf-8", "string", 69, 420, "string"
            )):
                hash_password(password)
    else:
        hashed = hash_password(password)
        assert verify_password(password, hashed)


@pytest.mark.parametrize("password, wrong_password", [
    ("password123", "wrongpass"),
    ("", "nonempty"),
    ("special@char", "special@chars"),
])
def test_verify_password_fail(password, wrong_password):
    """Test password verification fails for incorrect passwords."""
    hashed = hash_password(password)
    assert not verify_password(wrong_password, hashed)


@pytest.mark.parametrize("sub_data, exp_minutes", [
    (TokenData(purpose="login", uuid="user-uuid", roles=["user"]), 30),
    (TokenData(purpose="reset-password", uuid="reset-uuid", username="testuser"), 60),
    (TokenData(purpose="email-verification",
     uuid="verify-uuid", email="test@example.com"), 5),
])
def test_create_and_decode_access_token(sub_data, exp_minutes):
    """Test creating and decoding access tokens with various payloads."""
    token = create_access_token(
        sub=sub_data, exp=exp_minutes)
    decoded = decode_access_token(token.token_type + " " + token.access_token)
    assert decoded.purpose == sub_data.purpose
    assert decoded.uuid == sub_data.uuid


@pytest.mark.parametrize("token, strict, decoded_token", [
    ("WRONG invalid-token-type", True, {}),
    ("Bearer invalid-token", False, DecodeError()),
    ("NoClaims", False, {}),
    ("Wrong Issuer", False, {"iss": "wrong-issuer"}),
    ("Too Early", False, {
        "iss": settings.PROJECT_NAME,
        "iat": str(int(datetime(year=3000, month=1, day=1, tzinfo=timezone.utc).timestamp()))
    }),
    ("Too Late", False, {
        "iss": settings.PROJECT_NAME,
        "iat": str(int((datetime.now(timezone.utc)-timedelta(days=365)).timestamp())),
        "exp": str(int(timedelta(minutes=1).total_seconds()))
    })

])
def test_decode_access_token_invalid(token, strict, decoded_token):
    """Test decoding invalid access tokens."""
    with pytest.raises(HTTPException):
        if isinstance(decoded_token, Exception):
            with patch("authlib.jose.jwt.decode", side_effect=decoded_token):
                decode_access_token(token, strict)
        else:
            with patch("authlib.jose.jwt.decode", return_value=decoded_token):
                decode_access_token(token, strict)


def test_decode_access_token_invalid_sub():
    """Test decoding invalid access tokens."""
    with pytest.raises(HTTPException):
        with patch("authlib.jose.jwt.decode", return_value={
            "iss": settings.PROJECT_NAME,
            "iat": str(int((datetime.now(timezone.utc)-timedelta(minutes=1)).timestamp())),
            "exp": str(int(timedelta(minutes=30).total_seconds())),
            "sub": {"purpose": "bad_purpose", "uuid": "wrong-uuid"}
        }):
            decode_access_token("Wrong Sub", False)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "existing_secret, expect_db_write, raises_error",
    [
        # New secret should be generated and stored in DB
        (None, True, False),
        # New secret should be generated and stored in DB (placeholder secret)
        ("changeme", True, False),
        # Use existing secret, no DB interaction
        ("existingsecret", False, False),
        # Simulate DB error and ensure rollback is called
        (None, True, True),
    ]
)
async def test_generate_otp_parametrized(mock_db_session, existing_secret, expect_db_write, raises_error):
    """Test generate_otp function with different scenarios using parametrization."""
    user_uuid = "test-uuid"
    user_username = "testuser"
    generated_secret = "newrandomsecret"

    # Mock the User model and query result
    # User_DB = MagicMock()
    mock_user_instance = MagicMock()

    # Handle DB query/mock based on error scenario
    if raises_error:
        mock_db_session.query.return_value.filter.return_value.first.side_effect = IntegrityError(
            statement="Error", params="Error", orig="Error"
        )
    else:
        mock_db_session.query.return_value.filter.return_value.first.return_value = mock_user_instance

    with (patch('app.core.security.generate_random_letters', return_value=generated_secret),
            patch('pyotp.TOTP.provisioning_uri', return_value="otpauth://test-uri")):

        if raises_error:
            with pytest.raises(IntegrityError):
                await generate_otp(mock_db_session, user_uuid, user_username, existing_secret)
            mock_db_session.rollback.assert_called_once()
        else:
            uri, secret = await generate_otp(mock_db_session, user_uuid, user_username, existing_secret)
            assert uri == "otpauth://test-uri"
            assert secret == (
                generated_secret if expect_db_write else existing_secret)
            if expect_db_write:
                mock_user_instance.otp_secret = generated_secret
                mock_db_session.add.assert_called_once_with(mock_user_instance)
                mock_db_session.commit.assert_called_once()
                mock_db_session.refresh.assert_called_once_with(
                    mock_user_instance)
            else:
                mock_db_session.add.assert_not_called()
                mock_db_session.commit.assert_not_called()


@pytest.mark.parametrize("otp_method, expected", [
    ("authenticator", True),
    ("email", True),
    ("none", True),
    ("no-secret", False),
    ("OTHER", HTTPException(status_code=400, detail="Invalid OTP method")),
])
def test_validate_otp(otp_method, expected):
    """Test OTP validation with various methods and secrets."""
    if isinstance(expected, HTTPException):
        with pytest.raises(HTTPException):
            validate_otp("TOTP.name", "TOTP.secret",
                         "TOTP.now()", otp_method)
    else:
        totp = pyotp.TOTP(
            s=generate_random_letters(length=32),
            name="mock_user",
            interval=settings.OTP_EMAIL_INTERVAL if otp_method == "email" else settings.OTP_AUTHENTICATOR_INTERVAL,
            issuer=settings.PROJECT_NAME,
            digits=settings.OTP_LENGTH
        )
        otp = totp.now()
        if otp_method == "no-secret":
            assert not validate_otp(totp.name, None, otp, otp_method)
        else:
            result = validate_otp(totp.name, totp.secret, otp, otp_method)
            assert result == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("data, expected_result", [
    # admin@example.com / inactive
    ({
        "username": "admin@example.com",
        "password": "password",
        "active": False,
        "otp_secret": "test-otp-secret",
        "otp_method": "none"
    }, HTTPException(status_code=400)),
    # inactive WITH history
    ({
        "username": "no_history",
        "password": "password",
        "active": False,
        "otp_secret": "",
        "otp_method": "authenticator"
    }, HTTPException(status_code=401)),
    # Valid User / OTP NONE
    ({
        "username": "testuser",
        "password": "password",
        "active": True,
        "otp_secret": "test-otp-secret",
        "otp_method": "none"
    }, True),
    # Not None OTP
    ({
        "username": "testuser",
        "password": "password",
        "active": True,
        "otp_secret": generate_random_letters(32),
        "otp_method": "email"
    }, HTTPException(status_code=401)),
    # Wrong Password
    ({
        "username": "testuser",
        "password": "wrongpassword",
        "active": True,
        "otp_secret": "test-otp-secret",
        "otp_method": "authenticator"
    }, HTTPException(status_code=401)),
    # No secret
    ({
        "username": "testuser",
        "password": "password",
        "active": True,
        "otp_secret": None,
        "otp_method": "authenticator"
    }, HTTPException(status_code=401)),
    # No User
    ({
        "username": "none",
        "password": "password",
        "active": True,
        "otp_secret": "",
        "otp_method": "authenticator"
    }, HTTPException(status_code=401)),
])
async def test_authenticate_user(mock_db_session, mock_user, data, expected_result):
    """Test user authentication with valid and invalid credentials."""
    mock_user.is_active = data["active"]
    mock_user.otp_secret = data["otp_secret"]
    mock_user.otp_method = data["otp_method"]
    if data["username"] == "no_history":
        mock_user.user_history = ["BANNED", "LOCKED"]
    mock_db_session.query.return_value.filter.return_value.first.return_value = mock_user

    if isinstance(expected_result, HTTPException):
        with pytest.raises(HTTPException):
            with (
                patch("app.core.email.send_otp_email", return_value=True),
                patch("app.core.security.generate_otp",
                      return_value=data["otp_secret"] or "test-otp-secret"),
                patch("app.db_objects.user.get_user_by_email",
                      return_value=None if (data["username"] in ("admin@example.com", "none")) else mock_user),
                patch(
                    "app.db_objects.user.get_user_by_username",
                    return_value=None if (
                        data["username"] == "none") else mock_user
                )
            ):
                await authenticate_user(mock_db_session, data["username"], data["password"])
    else:
        user = await authenticate_user(mock_db_session, data["username"], data["password"])
        assert user == mock_user
