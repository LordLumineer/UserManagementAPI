"""
Module to handle permissions for the API.

This module contains the permissions for the API. The permissions are
defined as a dictionary with the resource as the key and a dictionary
with the method as the key and a boolean indicating if the user has
permission to perform the action as the value.

The permissions are grouped by role, with the role name as the key.
The roles are:

- admin: the administrator role.
- moderator: the moderator role.
- user: the user role.

The functions in this module are used to check if a user has permission
to perform an action on a resource.

"""
from functools import wraps
import hashlib
import inspect
import json
import os
import re
from typing import Callable, Literal, Union

from fastapi import HTTPException
from pydantic import BaseModel

from app.core.config import settings, logger
from app.db_objects.db_models import (
    User,
    File,
    ExternalAccount,
    OAuthToken
)

# ----- PERMISSIONS ----- #
UserRole = Literal["user", "tester", "moderator", "admin"]

PermissionCheck = Union[bool, Callable[[
    User, Union[File, User, File, ExternalAccount, OAuthToken]], bool]]

RolesWithPermissions = dict[
    UserRole,
    dict[str, dict[str, PermissionCheck]]
]

ROLES: RolesWithPermissions = {
    "admin": {
        "user": {
            "create": True,
            "read": True,
            "update": True,
            "delete": True
        },
        "user_image": {
            "create": True,
            "read": True,
            # "update": True,
            # "delete": True
        },
        "user_file": {
            "create": True,
            # "read": True,
            # "update": True,
            # "delete": True
        },
        "blocked_users": {
            "create": True,
            # "read": True,
            "update": True,
            "delete": True,
        },
        "file": {
            "create": True,
            "read": True,
            "update": True,
            "delete": True
        },
        "database": {
            "export": True,
            "backup": True,
            "import": True,
            "restore": True,
        },
        "email": {
            "single": True,
            "multiple": True,
            "all": True,
            "test": True,
            "auth": True
        },
        "admin": {
            "ban": True,
            "unban": True,
            "feature_flags": True
        },
        "docs": {
            "swagger": True,
            "redoc": True
        },
    },
    "moderator": {
        "user": {
            "create": lambda user, new_user: not list(set(["admin", "moderator"]) & set(new_user.roles)),
            "read": True,
            "update": lambda user, data: (
                not list(set(["admin", "moderator"]) & set(data["db_user"].roles)) and
                not list(set(["admin", "moderator"]) &
                         set(data["updates"].roles or []))
            ),
            "delete": False
        },
        "user_image": {
            "create": False,
            "read": True,
            # "update": True,
            # "delete": True
        },
        "user_file": {
            "create": False,
            # "read": True,
            # "update": True,
            # "delete": True
        },
        "blocked_users": {
            "create": False,
            # "read": True,
            "update": False,
            "delete": False,
        },
        "file": {
            "create": True,
            "read": True,
            "update": True,
            "delete": False
        },
        "email": {
            "single": True,
            "multiple": True,
            "all": False,
            "test": False,
            "auth": True
        },
        "admin": {
            "ban": lambda user, other_user: not list(set(["admin", "moderator"]) & set(other_user.roles)),
            "unban": False,
            "feature_flags": False
        },
        "docs": {
            "swagger": False,
            "redoc": True
        },
    },
    "user": {
        "user": {
            "create": False,
            "read": lambda user, other_user: (
                user.uuid not in other_user.blocked_uuids and
                other_user.uuid not in user.blocked_uuids and
                other_user.is_active
            ),
            "update": lambda user, other_user: (
                user.uuid == other_user.uuid and
                other_user.roles is None
            ),
            "delete": lambda user, other_user: user.uuid == other_user.uuid
        },
        "user_image": {
            "create": lambda user, other_user: user.uuid == other_user.uuid,
            "read": lambda user, other_user: (
                user.uuid not in other_user.blocked_uuids and
                other_user.uuid not in user.blocked_uuids and
                other_user.is_active
            ),
            # "update": True,
            # "delete": True
        },
        "user_file": {
            "create": lambda user, other_user: user.uuid == other_user.uuid,
            # "read": True,
            # "update": True,
            # "delete": True
        },
        "blocked_users": {
            "create": lambda user, other_user: user.uuid == other_user.uuid,
            # "read": lambda user, other_user: user.uuid == other_user.uuid,
            "update": lambda user, other_user: user.uuid == other_user.uuid,
            "delete": lambda user, other_user: user.uuid == other_user.uuid,
        },
        "file": {
            "create": True,
            "read": lambda user, file: (
                user.uuid not in file.created_by.blocked_uuids and
                file.created_by.uuid not in user.blocked_uuids
            ),
            "update": lambda user, file: user.uuid == file.created_by_uuid,
            "delete": lambda user, file: user.uuid == file.created_by_uuid
        },
        "docs": {
            "swagger": False,
            "redoc": True
        },
    },
}


def has_permission(user: User, resource: str, action: str, data=None, raise_error: bool = True) -> bool:
    """
    Checks if a user has permission to perform an action on a resource.

    :param User user: The user to check the permission for.
    :param str resource: The resource to check the permission for.
    :param str action: The action to check the permission for.
    :param object data: The data to pass to the permission function.
    :return bool: True if the user has permission, False otherwise.

    Notes
    -----
    The function checks the permission for each role the user has.
    If the user has multiple roles, the function checks the next role 
        if the first role does not have the permission.
    The function returns False if the user does not have permission.
    """
    for role in user.roles:
        permission = ROLES.get(role, {}).get(resource, {}).get(action)
        if permission is None:
            continue
        has_access = False
        if isinstance(permission, bool):
            has_access = permission
        elif callable(permission) and data is not None:
            has_access = permission(user, data)
        if has_access:
            return has_access
        # If the user has multiple roles checks the next role
    if raise_error:
        raise HTTPException(status_code=403, detail="Forbidden")
    return False


# ----- FEATURE FLAGS ----- #

FEATURE_FLAGS = {}


class FeatureFlagRule(BaseModel):
    """Feature flag rule."""
    percentageOfUsers: float | None = None
    userRoles: list[UserRole] | None = None


# class FeatureFlag(BaseModel):
#     name: str
#     rule: bool | list[FeatureFlagRule]
FeatureFlags = dict[str, bool | list[FeatureFlagRule]]


def load_feature_flags(app_endpoint_functions_name: list[str] = None):
    """Load feature flags from a file into memory."""
    if app_endpoint_functions_name is None:
        app_endpoint_functions_name = []
    global FEATURE_FLAGS  # pylint: disable=global-statement
    if os.path.exists(settings.FEATURE_FLAGS_FILE):
        with open(settings.FEATURE_FLAGS_FILE, "r", encoding="utf-8") as file:
            FEATURE_FLAGS = json.load(file)
    else:
        FEATURE_FLAGS = {}
    # Update the feature flags based on the app endpoint functions name
    for endpoint_function_name in app_endpoint_functions_name:
        if endpoint_function_name not in FEATURE_FLAGS:
            FEATURE_FLAGS[endpoint_function_name] = True
    save_feature_flags()
    return FEATURE_FLAGS


def save_feature_flags():
    """Save feature flags from memory to a file."""
    with open(settings.FEATURE_FLAGS_FILE, "w", encoding="utf-8") as file:
        json.dump(FEATURE_FLAGS, file, indent=4)
    return FEATURE_FLAGS


def user_has_valid_role(allowed_roles: list[UserRole] | None, user_role: UserRole) -> bool:
    """Check if the user's role is among the allowed roles.

    :param list[UserRole] | None allowed_roles: A list of roles that are allowed access, 
                                                or None if all roles are allowed.
    :param UserRole user_role: The role of the user to check.
    :return bool: True if the user's role is valid, False otherwise.
    """
    return allowed_roles is None or user_role in allowed_roles


def user_is_within_percentage(feature_name: str, allowed_percent: float | None, flag_id: str) -> bool:
    """
    Check if the user is within the allowed percentage of users for the feature.

    :param str feature_name: The name of the feature to check.
    :param float | None allowed_percent: The percentage of users that are allowed access to the feature.
    :param str flag_id: The id of the flag to check.
    :return bool: True if the user is within the allowed percentage, False otherwise.

    Notes
    -----
    The function uses a SHA256 hash of the feature name and flag id to generate a
        pseudo-random number between 0 and 2^32 - 1.
    The function then checks if the user's id is within the allowed percentage of
        users by comparing the hashed id to the allowed percentage.
    The function returns True if the user is within the allowed percentage, False
        otherwise.
    """
    if allowed_percent is None:
        return True
    data = f"{feature_name}-{flag_id}"
    hashed_value = int(hashlib.sha256(data.encode()).hexdigest()[:8], 16)
    return hashed_value / int(2**32 - 1) < allowed_percent


def can_view_feature(feature_name: str, db_user: User | None) -> bool:
    """
    Check if the user can view a feature.

    :param str feature_name: The name of the feature to check.
    :param User | None db_user: The user object of the user to check.
    :return bool: True if the user can view the feature, False otherwise.

    Notes
    -----
    The function checks if the user has a role that is allowed access to the feature
        and if the user is within the allowed percentage of users.
    If the user is not logged in, the function will return True if the feature is not
        configured to require login, False otherwise.
    If the feature is not configured, the function will return True.
    The function will log a critical error message if the feature is misconfigured.
    """
    rules = FEATURE_FLAGS.get(feature_name)
    if rules is None:
        return True

    if isinstance(rules, bool):
        return rules

    for rule in rules:
        if not db_user:
            logger.critical(
                f"Server error <{feature_name}>: Misconfigured feature flag")
            raise HTTPException(
                status_code=500,
                detail=f"Server error: Misconfigured feature flag, contact support: {
                    settings.CONTACT_EMAIL}"
            )
        if (
            next((True for role in db_user.roles if user_has_valid_role(rule.get("userRoles"), role)), False) and
            user_is_within_percentage(feature_name, rule.get(
                "percentageOfUsers"), db_user.uuid)
        ):
            return True

    return False


def feature_flag(feature_name: str):
    """Decorator to enforce feature flag access.

    :param str feature_name: The name of the feature to check.
    :return Callable: The decorated function.

    Notes
    -----
    The decorator will set the `_feature_name` attribute of the decorated function to the given feature name.
    The decorated function will be replaced with a wrapper that checks if the user can view the feature.
    If the user is not logged in, the wrapper will return a 401 Unauthorized response.
    If the user is logged in, but does not have access to the feature, the wrapper will
        return a 403 Forbidden response.
    If the user has access to the feature, the wrapper will call the original function.
    """
    def decorator(func):
        func._feature_name = feature_name  # pylint: disable=W0212

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        # Determine if the function is async or sync
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
