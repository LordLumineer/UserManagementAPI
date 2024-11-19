import re
from tkinter import N
from unittest.mock import mock_open, patch
from annotated_types import T
import pytest
import os
import platform
import httpx

from fastapi import HTTPException
from fastapi.routing import APIRoute

from app.core.config import settings, logger
from app.core.utils import (
    validate_username,
    validate_email,
    validate_password,
    generate_random_letters,
    generate_random_digits,
    generate_uuid,
    generate_timestamp,
    extract_initials_from_text,
    custom_generate_unique_id,
    render_html_template,
    not_found_page,
    remove_file,
    extract_info,
    get_location_from_ip,
    get_info_from_request,
    detect_docker,
    get_machine_info,
    get_latest_commit_info,
    get_repository_info
)


@pytest.mark.parametrize("username, expected", [
    ("valid_user", "valid_user"),
    ("user123", "user123"),
    ("invalid user", pytest.raises(HTTPException)),
    ("aB12", pytest.raises(HTTPException))
])
@pytest.mark.parametrize("mock_settings", [
    {"ENVIRONMENT": "local"},
    {"ENVIRONMENT": "production"}
], indirect=True)
def test_validate_username(username, expected, mock_settings):
    if isinstance(expected, str):
        assert validate_username(username) == expected
    else:
        if mock_settings.ENVIRONMENT == "local":
            assert validate_username(username) == username
        else:
            with expected:
                validate_username(username)


@pytest.mark.parametrize("email, raise_error, expected", [
    ("admin@example.com", True, "admin@example.com"),
    ("valid@example.com", True, "valid@example.com"),
    ("invalid-email", True, pytest.raises(HTTPException)),
    ("invalid-email", False, False)
])
@pytest.mark.parametrize("mock_settings", [
    {"ENVIRONMENT": "local"},
    {"ENVIRONMENT": "production"}
], indirect=True)
def test_validate_email(email, raise_error, expected, mock_settings):
    if isinstance(expected, str):
        assert validate_email(email, raise_error, False) == expected
    elif expected is False:
        assert validate_email(email, raise_error, False) is False
    else:
        if mock_settings.ENVIRONMENT == "local":
            assert validate_email(email, raise_error, False) == email
        else:
            with expected:
                validate_email(email, raise_error, False)


@pytest.mark.parametrize("password, expected", [
    ("ValidPass1$", "ValidPass1$"),
    ("short1$", pytest.raises(HTTPException)),
    ("NoSpecialChar123", pytest.raises(HTTPException))
])
@pytest.mark.parametrize("mock_settings", [
    {"ENVIRONMENT": "local"},
    {"ENVIRONMENT": "production"}
], indirect=True)
def test_validate_password(password, expected, mock_settings):
    if isinstance(expected, str):
        assert validate_password(password) == expected
    else:
        if mock_settings.ENVIRONMENT == "local":
            assert validate_password(password) == password
        else:
            with expected:
                validate_password(password)


@pytest.mark.parametrize("length, seed", [
    (5, 42),
    (5, None),
])
def test_generate_random_letters(length, seed):
    with patch("time.time") as mock_time:
        result = generate_random_letters(length, seed)
        if seed is None:
            assert mock_time.call_count == 2
        else:
            mock_time.assert_called_once()
    assert result.isalpha()
    assert isinstance(result, str)
    assert len(result) == length


@pytest.mark.parametrize("length, seed", [
    (5, 42),
    (5, None),
])
def test_generate_random_digits(length, seed):
    with patch("time.time") as mock_time:
        result = generate_random_digits(length, seed)
        if seed is None:
            assert mock_time.call_count == 2
        else:
            mock_time.assert_called_once()
    assert result.isnumeric()
    assert isinstance(result, str)
    assert len(result) == length


def test_generate_uuid():
    result = generate_uuid()
    assert isinstance(result, str)
    assert len(result) == 36  # UUID standard length


def test_generate_timestamp():
    result = generate_timestamp()
    assert isinstance(result, int)
    assert result > 0


@pytest.mark.parametrize("text, expected", [
    ("OpenAI GPT", "OG"),
    ("This is a Test", "TIAT"),
    ("singleword", "S")
])
def test_extract_initials_from_text(text, expected):
    assert extract_initials_from_text(text) == expected


def test_render_html_template():
    html = "<p>{{ PROJECT_NAME }} | {{ OTHER_VAR }}</p>"
    rendered = render_html_template(html)
    assert "PROJECT_NAME" not in rendered
    assert "{{ OTHER_VAR }}" in rendered


@pytest.mark.parametrize("exists", [
    (True),
    (False)
])
def test_remove_file(exists):
    with patch("os.path.exists", return_value=exists):
        with patch("os.remove") as mock_remove:
            remove_file("/fake/path/to/file")
            if exists:
                mock_remove.assert_called_once_with("/fake/path/to/file")
            else:
                mock_remove.assert_not_called()


@pytest.mark.parametrize(
    "exists_return_value, open_side_effect, expected_result",
    [
        # Case 1: '/.dockerenv' exists, so it should return True
        (True, None, True),

        # Case 2: '/.dockerenv' does not exist, but '/proc/self/cgroup' contains 'docker', so it should return True
        (False, "1:cpu:/docker", True),

        # Case 3: Neither '/.dockerenv' exists, nor 'docker' is found in '/proc/self/cgroup', should return False
        (False, "1:cpu:/some_other_group", False),

        # Case 4: '/.dockerenv' does not exist, and '/proc/self/cgroup' cannot be opened (FileNotFoundError), should return False
        (False, FileNotFoundError, False)
    ]
)
def test_detect_docker(exists_return_value, open_side_effect, expected_result):
    with patch("os.path.exists", return_value=exists_return_value):
        if open_side_effect == FileNotFoundError:
            with patch("builtins.open", side_effect=open_side_effect):
                result = detect_docker()
                assert result == expected_result
        else:
            with patch("builtins.open", mock_open(read_data=open_side_effect)):
                result = detect_docker()
                assert result == expected_result


@pytest.mark.parametrize(
    "system, platform_name, version, release, architecture, processor, cpu_count, python_version, is_docker, details, expected_machine_info",
    [
        # Case 1: Windows system
        ("Windows", "Windows-10-10.0.18362-SP0", "10.0.18362", "10", "x86_64", "Intel", 4, "3.8.5", True,
         {"win32_ver": ("10", "10.0.18362"),
          "win32_is_iot": False, "win32_edition": "Home"},
         {
             "platform": "Windows-10-10.0.18362-SP0",
             "system": "Windows",
             "version": "10.0.18362",
             "release": "10",
             "architecture": "x86_64",
             "processor": "Intel",
             "cpu_count": 4,
             "python_version": "3.8.5",
             "is_docker": True,
             "details": {"win32_ver": ("10", "10.0.18362"), "win32_is_iot": False, "win32_edition": "Home"}
         }),

        # Case 2: Linux system
        ("Linux", "Linux-5.4.0-80-generic-x86_64-with-Ubuntu-20.04-focal", "5.4.0-80", "5.4.0", "x86_64", "x86_64", 8, "3.8.5", False,
         {"freedesktop_os_release": "Ubuntu 20.04"},
         {
             "platform": "Linux-5.4.0-80-generic-x86_64-with-Ubuntu-20.04-focal",
             "system": "Linux",
             "version": "5.4.0-80",
             "release": "5.4.0",
             "architecture": "x86_64",
             "processor": "x86_64",
             "cpu_count": 8,
             "python_version": "3.8.5",
             "is_docker": False,
             "details": {"freedesktop_os_release": "Ubuntu 20.04"}
         }),

        # Case 3: macOS system
        ("Darwin", "Darwin-19.6.0-x86_64", "19.6.0", "19.6.0", "x86_64", "Intel", 4, "3.8.5", True,
         {"mac_ver": ("10.15.6", "x86_64", "macOS")},
         {
             "platform": "Darwin-19.6.0-x86_64",
             "system": "Darwin",
             "version": "19.6.0",
             "release": "19.6.0",
             "architecture": "x86_64",
             "processor": "Intel",
             "cpu_count": 4,
             "python_version": "3.8.5",
             "is_docker": True,
             "details": {"mac_ver": ("10.15.6", "x86_64", "macOS")}
         }),

        # TODO: Case 4: iOS/iPadOS system

        # TODO: Case 5: Android system

        # TODO: Case 6: Unknown system
    ]
)
def test_get_machine_info(system, platform_name, version, release, architecture, processor, cpu_count, python_version, is_docker, details, expected_machine_info):
    # Mocking the platform and os methods
    with patch("platform.platform", return_value=platform_name), \
            patch("platform.system", return_value=system), \
            patch("platform.version", return_value=version), \
            patch("platform.release", return_value=release), \
            patch("platform.machine", return_value=architecture), \
            patch("platform.processor", return_value=processor), \
            patch("os.cpu_count", return_value=cpu_count), \
            patch("platform.python_version", return_value=python_version), \
            patch("app.core.utils.detect_docker", return_value=is_docker):

        # Mocking system-specific details
        if system == "Windows":
            with patch("platform.win32_ver", return_value=("10", "10.0.18362")), \
                    patch("platform.win32_is_iot", return_value=False), \
                    patch("platform.win32_edition", return_value="Home"):
                result = get_machine_info()
                assert result == expected_machine_info
        elif system == "Linux":
            with patch("platform.freedesktop_os_release", return_value="Ubuntu 20.04"):
                result = get_machine_info()
                assert result == expected_machine_info
        elif system == "Darwin":
            with patch("platform.mac_ver", return_value=("10.15.6", "x86_64", "macOS")):
                result = get_machine_info()
                assert result == expected_machine_info
        else:
            ...


# def test_get_latest_commit_info(mocker):
#     mock_subprocess = mocker.patch(
#         "subprocess.check_output", return_value="hash\n2024-11-17\nAuthor Name\nauthor@example.com\nSubject\nBody")
#     commit_info = get_latest_commit_info()
#     assert commit_info["author_name"] == "Author Name"
#     assert commit_info["hash"] == "hash"


# def test_get_repository_info(mocker):
#     mock_subprocess = mocker.patch("subprocess.check_output")
#     mock_subprocess.side_effect = [
#         "https://github.com/user/repo.git\n",  # remote URL
#         "main\n",  # branch name
#         "Remote Details\n",  # remote show
#         "https://github.com/user/repo.git\n"  # push URL
#     ]
#     repo_info = get_repository_info()
#     assert repo_info["repo_name"] == "repo"
#     assert repo_info["branch_name"] == "main"
