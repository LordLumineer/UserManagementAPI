from email.policy import HTTP
import json
import os
import aiofiles
from fastapi.testclient import TestClient
import pytest
from fastapi import FastAPI, HTTPException
from app.core.middleware import FeatureFlagMiddleware
from app.db_objects.db_models import User, File


from app.core.config import settings
from unittest.mock import patch, AsyncMock, mock_open
from app.core.permissions import (
    has_permission,
    user_has_valid_role,
    user_is_within_percentage,
    can_view_feature,
    load_feature_flags,
    save_feature_flags,
    feature_flag,
    FEATURE_FLAGS,
    FeatureFlagRule
)


@pytest.fixture
def user():
    return User(uuid="user-uuid", roles=["user"], blocked_uuids=[], is_active=True)


@pytest.fixture
def admin():
    return User(uuid="admin-uuid", roles=["admin"], blocked_uuids=[], is_active=True)


@pytest.fixture
def file():
    return File(uuid="file-uuid", created_by_uuid="user-uuid", created_by=User(uuid="user-uuid", roles=["user"], blocked_uuids=[], is_active=True))


@pytest.mark.parametrize("role, action, target_user, expected", [
    ("user", "read", User(uuid="other-user-uuid",
     roles=["user"], blocked_uuids=[], is_active=True), True),
    ("user", "update", User(uuid="user-uuid", roles=None,
     blocked_uuids=[], is_active=True), True),
    ("user", "delete", User(uuid="user-uuid",
     roles=["user"], blocked_uuids=[], is_active=True), True),
    ("user", "create", None, HTTPException),  # Assuming user cannot create
    ("user", "something", None, False) # No permission
])
def test_has_permission_user(user, role, action, target_user, expected):
    if isinstance(expected, bool):
        if expected is False:
            assert has_permission(user, role, action, target_user, raise_error=False) == expected
        else:
            assert has_permission(user, role, action, target_user) == expected
    else:
        with pytest.raises(HTTPException):
            has_permission(user, role, action, target_user)


@pytest.mark.parametrize("role, action, expected", [
    ("user", "create", True),
    ("user", "read", True),
    ("user", "update", True),
    ("user", "delete", True),
])
def test_has_permission_admin(admin, role, action, expected):
    assert has_permission(admin, role, action) == expected


@pytest.mark.parametrize("roles, role, expected", [
    (["admin", "user"], "user", True),
    (["admin", "user"], "moderator", False),
    (None, "user", True),
])
def test_user_has_valid_role(roles, role, expected):
    assert user_has_valid_role(roles, role) == expected


@pytest.mark.parametrize("feature, percentage, user_uuid, expected", [
    ("feature", 1.0, "user-uuid", True),
    ("feature", 0.0, "user-uuid", False),
])
def test_user_is_within_percentage(feature, percentage, user_uuid, expected):
    assert user_is_within_percentage(
        feature, percentage, user_uuid) == expected


@pytest.mark.parametrize("feature_flag_value, expected", [
    (True, True),
    (False, False),
    ([FeatureFlagRule(userRoles=["user"]).model_dump()], True),
    ([FeatureFlagRule(percentageOfUsers=1.0, userRoles=["user"]).model_dump()], True),
    ([FeatureFlagRule(percentageOfUsers=0.0, userRoles=["user"]).model_dump()], False),
])
def test_can_view_feature(user, feature_flag_value, expected):
    FEATURE_FLAGS["test_feature"] = feature_flag_value
    assert can_view_feature("test_feature", user) == expected

def test_can_view_undefined_feature(user):
    assert can_view_feature("test_feature_2", user) == True

def test_can_view_feature_miss_configured(user):
    FEATURE_FLAGS["test_feature_3"] = [FeatureFlagRule(percentageOfUsers=1.0, userRoles=["user"]).model_dump()]
    with patch("app.core.permissions.logger") as mock_logger:
        with pytest.raises(HTTPException):
            assert can_view_feature("test_feature_3", None)
            mock_logger.critical.assert_called_once()

FakeApp = FastAPI()
FakeApp.add_middleware(FeatureFlagMiddleware)


@feature_flag("test_feature")
@FakeApp.get("/public-endpoint_1")
def _public_endpoint_1():
    return {"message": "This is public"}

@feature_flag("test_feature")
@FakeApp.get("/public-endpoint_2")
async def _public_endpoint_2():
    return {"message": "This is public"}


@pytest.fixture
def _client():
    return TestClient(FakeApp)


def test_feature_flag_decorator(_client):
    FEATURE_FLAGS["test_feature"] = True
    response = _client.get("/public-endpoint_1")
    assert response.status_code == 200
    assert response.json() == {"message": "This is public"}

    response = _client.get("/public-endpoint_2")
    assert response.status_code == 200
    assert response.json() == {"message": "This is public"}

    FEATURE_FLAGS["test_feature"] = False
    response = _client.get("/public-endpoint_1")
    assert response.status_code == 403
    assert response.json()[
        "error"] == "Access to feature '_public_endpoint_1:test_feature' is denied."


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_flags, app_endpoint_functions_name", [
    (None, ["test_feature"]),
    (["existing_feature_1", "existing_feature_2"], None),
    ])
async def test_load_save_feature_flags(existing_flags, app_endpoint_functions_name):
    filename = "test_feature_flags.json"
    settings.FEATURE_FLAGS_FILE = filename
    if existing_flags is None:
        if os.path.exists(settings.FEATURE_FLAGS_PATH):
            os.remove(settings.FEATURE_FLAGS_PATH)
        feature_flags = await load_feature_flags(app_endpoint_functions_name)
        assert feature_flags["test_feature"] == True
        assert len(feature_flags) == len(app_endpoint_functions_name)
    else:
        async with aiofiles.open(settings.FEATURE_FLAGS_PATH, 'x', encoding='utf-8') as f:
            features = {}
            for feature in existing_flags:
                features[feature] = True
            await f.write(json.dumps(features, indent=4))
        feature_flags = await load_feature_flags(app_endpoint_functions_name)
        assert feature_flags[existing_flags[0]] == True
        assert len(feature_flags) == len(existing_flags)

    os.remove(settings.FEATURE_FLAGS_PATH)
