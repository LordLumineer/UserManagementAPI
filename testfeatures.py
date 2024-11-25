import inspect
from functools import wraps
from typing import Callable, Dict, List, Literal, TypedDict, Union
import hashlib
from datetime import datetime

from pydantic import BaseModel

# Define UserRole and User
UserRole = Literal["user", "admin", "moderator", "tester"]


class User(TypedDict):
    id: str
    roles: List[UserRole]
    blockedBy: List[str]

# Define Comment and Todo


class Comment(TypedDict):
    id: str
    body: str
    authorId: str
    createdAt: datetime


class Todo(TypedDict):
    id: str
    title: str
    userId: str
    completed: bool
    invitedUsers: List[str]
    
    def __repr__(self):
        return f"Comment(id={self.id}, body={self.title}, authorId={self.userId})"


# Define permissions-related types
PermissionCheck = Union[bool, Callable[[User, Union[Comment, Todo]], bool]]

RolesWithPermissions = Dict[
    UserRole,
    Dict[str, Dict[str, PermissionCheck]]
]


def feature_flag_required(feature_name: str | None = None):
    """Decorator to enforce feature flag access."""
    def decorator(func: Callable):
        if inspect.iscoroutinefunction(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                print(f"Checking feature flag {
                      feature_name}...{func.__name__}...")
                return await func(*args, **kwargs)
        else:
            @wraps(func)
            def wrapper(*args, **kwargs):
                print(f"Checking feature flag {
                      feature_name}...{func.__name__}...")
                return func(*args, **kwargs)
        return wrapper
    return decorator


# Permissions definition
ROLES: RolesWithPermissions = {
    "admin": {
        "comments": {
            "view": True,
            "create": True,
            "update": True,
        },
        "todos": {
            "view": True,
            "create": True,
            "update": True,
            "delete": True,
        },
    },
    "moderator": {
        "comments": {
            "view": True,
            "create": True,
            "update": True,
        },
        "todos": {
            "view": True,
            "create": True,
            "update": True,
            "delete": lambda user, todo: todo["completed"],
        },
    },
    "user": {
        "comments": {
            "view": lambda user, comment: comment["authorId"] not in user["blockedBy"],
            "create": True,
            "update": lambda user, comment: comment["authorId"] == user["id"],
        },
        "todos": {
            "view": lambda user, todo: todo["userId"] not in user["blockedBy"],
            "create": True,
            "update": lambda user, todo: todo["userId"] == user["id"] or user["id"] in todo["invitedUsers"],
            "delete": lambda user, todo: (todo["userId"] == user["id"] or user["id"] in todo["invitedUsers"]) and todo["completed"],
        },
    },
}

# Define permissions-checking function


@feature_flag_required("ADVANCED_ANALYTICS")
def has_perrrrmission(user: User, resource: str, action: str, data=None) -> bool:
    for role in user["roles"]:
        permissions = ROLES.get(role, {}).get(resource, {})
        permission = permissions.get(action)
        if permission is None:
            continue

        if isinstance(permission, bool):
            return permission
        elif callable(permission):
            return permission(user, data)

    return False


# Define feature flag management types
FeatureFlagName = Literal[
    "TEST_NEW_PRODUCTS_QUERY",
    "ADVANCED_ANALYTICS",
    "DISABLED_FEATURE",
    "EXPERIMENTAL_FEATURE",
    "MULTIPLE_ALLOWANCES"
]


class FeatureFlagRule(TypedDict, total=False):
    percentageOfUsers: float
    userRoles: List[UserRole]


FEATURE_FLAGS: Dict[FeatureFlagName, Union[bool, List[FeatureFlagRule]]] = {
    "TEST_NEW_PRODUCTS_QUERY": True,
    "ADVANCED_ANALYTICS": True,
    "DISABLED_FEATURE": False,
    "EXPERIMENTAL_FEATURE": False,
    "MULTIPLE_ALLOWANCES": [
        {"percentageOfUsers": 0.25, "userRoles": ["user"]},
        {"userRoles": ["admin", "tester"]},
    ],
}

MAX_UINT_32 = 4294967295


def murmurhash(data: str) -> int:
    """Simple murmurhash-like implementation using hashlib."""
    return int(hashlib.sha256(data.encode()).hexdigest()[:8], 16)


def user_has_valid_role(allowed_roles: List[UserRole] | None, user_role: UserRole) -> bool:
    """Check if the user's role is valid for the feature."""
    return allowed_roles is None or user_role in allowed_roles


def user_is_within_percentage(feature_name: FeatureFlagName, allowed_percent: float | None, flag_id: str) -> bool:
    """Check if the user is within the allowed percentage of users for the feature."""
    if allowed_percent is None:
        return True
    hashed_value = murmurhash(f"{feature_name}-{flag_id}")
    print(hashed_value / MAX_UINT_32)
    return hashed_value / MAX_UINT_32 < allowed_percent


def check_rule(rule: FeatureFlagRule, feature_name: FeatureFlagName, user: User) -> bool:
    """Evaluate a single rule for a feature flag."""
    user_roles = rule.get("userRoles")
    percentage_of_users = rule.get("percentageOfUsers")
    return (
        user_has_valid_role(user_roles, user["roles"][0]) and
        user_is_within_percentage(
            feature_name, percentage_of_users, user["id"])
    )


def can_view_feature(feature_name: FeatureFlagName, user: User) -> bool:
    """Determine if a user can view a feature."""
    rules = FEATURE_FLAGS[feature_name]
    if isinstance(rules, bool):
        return rules
    return any(check_rule(rule, feature_name, user) for rule in rules)


# USAGE:
user: User = {"id": "12345", "roles": ["user"], "blockedBy": ["54321"]}

todo: Todo = {
    "id": "1",
    "title": "Test Todo",
    "userId": "12345",
    "completed": False,
    "invitedUsers": []
}

# Check permission for a Todo resource
print("Permission to view todo:", has_permission(user, "todos", "view", todo))

# Check feature flag visibility
print("Can view MULTIPLE_ALLOWANCES feature:",
      can_view_feature("MULTIPLE_ALLOWANCES", user))

