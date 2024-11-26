"""Tests for the core utilities module."""
from collections import namedtuple
from io import BytesIO
import os
import subprocess
from unittest.mock import MagicMock, mock_open, patch
from warnings import warn
# import os
# import platform
# import httpx

# from fastapi.routing import APIRoute
from fastapi.responses import HTMLResponse
from fastapi.exceptions import HTTPException
import pytesseract
import pytest
from PIL import Image

# from app.core.config import settings, logger
from app.core.utils import (
    app_path,
    generate_profile_picture,
    parse_remote_details,
    validate_username,
    validate_email,
    validate_password,
    generate_random_letters,
    generate_random_digits,
    generate_uuid,
    generate_timestamp,
    extract_initials_from_text,
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

# pylint: disable=C0116


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
    ("Only Fans", "OF"),
    ("Twitch Integration Throwing System", "TITS"),
    ("Bear", "B")
])
def test_extract_initials_from_text(text, expected):
    assert extract_initials_from_text(text) == expected


@pytest.mark.parametrize("test_letters, ocr, length_error", [
    ("AB", True, False),
    ("AZERTYQWERTY"*100, False, True),
])
@pytest.mark.asyncio
async def test_generate_profile_picture(test_letters, ocr, length_error):
    # Call the function
    if length_error:
        with pytest.raises(HTTPException):
            await generate_profile_picture(letters=test_letters)
        return "HTTPException raised as expected"
    response = await generate_profile_picture(letters=test_letters)

    # Check content type
    assert response.media_type == "image/png", "Response media type should be 'image/png'"

    # Verify that the returned content is a valid image
    img_data = response.body  # Access the binary image data from the response
    assert img_data is not None, "Response body should not be None"

    # Load the image using PIL
    img = Image.open(BytesIO(img_data))

    # Check image dimensions
    assert img.size == (100, 100), "Image dimensions should be 100x100"

    # Check image mode (it should be RGB)
    assert img.mode == "RGB", "Image mode should be RGB"

    # Check if the image contains the expected text
    if ocr:
        try:
            pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract'
            extracted_text = pytesseract.image_to_string(
                img, config="--psm 7").strip()
            assert extracted_text == test_letters, f"Expected '{
                test_letters}', but got '{extracted_text}'"
        except pytesseract.pytesseract.TesseractNotFoundError as e:
            warn(f"Tesseract not found: {e} | Skipping image verification.")

    # Check for errors when attempting to load the image
    try:
        img = Image.open(BytesIO(img_data))
        img.verify()  # Verifies the integrity of the image
    except (OSError, SyntaxError) as e:
        pytest.fail(f"Image verification failed with error: {e}")


def test_render_html_template():
    html = "<p>{{ PROJECT_NAME }} | {{ OTHER_VAR }}</p>"
    rendered = render_html_template(html)
    assert "PROJECT_NAME" not in rendered
    assert "{{ OTHER_VAR }}" in rendered


@pytest.mark.parametrize(
    "input_path, expected",
    [
        ("subdir/file.txt", "/mock/app/root/subdir/file.txt"),
        ("../file.txt", "/mock/app/file.txt"),
        ("", "/mock/app/root"),
        ("/absolute/path", "/absolute/path"),
    ]
)
def test_app_path(input_path, expected):
    with patch("app.core.config.settings.APP_ROOT_DIR", "/mock/app/root"):
        assert app_path(input_path) == os.path.normpath(expected)


def test_not_found_page():
    # Mock HTML content of the 404 template
    mock_html_content = "<html><body><h1>404 - Not Found</h1></body></html>"
    mock_rendered_html = "<html><body><h1>Page Not Found</h1></body></html>"

    # Mock the open function and render_html_template
    with patch("builtins.open", mock_open(read_data=mock_html_content)) as mock_file:
        with patch("app.core.utils.render_html_template", return_value=mock_rendered_html) as mock_render:
            response = not_found_page()

            # Validate the response
            assert isinstance(
                response, HTMLResponse), "Response should be an HTMLResponse"
            assert response.status_code == 404, "Response status code should be 404"
            assert response.body.decode(
                "utf-8") == mock_rendered_html, "Response content should match rendered HTML"

            # Verify file read
            mock_file.assert_called_once_with(
                "./templates/html/404.html", "r", encoding="utf-8")

            # Verify template rendering
            mock_render.assert_called_once_with(mock_html_content)


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


@pytest.mark.parametrize("user_agent, expected_os, expected_browser", [
    ("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/132.0",
     "X11; Ubuntu; Linux x86_64; rv:89.0", "Firefox"),
    ("Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
     "Windows NT 10.0; Trident/7.0; rv:11.0", "Internet Explorer"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_1) AppleWebKit/605.1.15 (KHTML, like Gecko) "
     "Version/18.0 Safari/605.1.15",
     "Macintosh; Intel Mac OS X 14_7_1", "Safari"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Safari/537.36",
     "Windows NT 10.0; Win64; x64", "Chrome"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.51",
     "Windows NT 10.0; Win64; x64", "Edge"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Safari/537.36 OPR/114.0.0.0",
     "Windows NT 10.0; Win64; x64", "Opera"),
    ("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Safari/537.36 Vivaldi/7.0.3495.15",
     "Windows NT 10.0; WOW64", "Vivaldi"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 YaBrowser/24.10.1.669 Yowser/2.5 Safari/537.36",
     "Windows NT 10.0; Win64; x64", "Yandex"),
    ("Unknown User-Agent String", "Unknown OS", "Unknown Browser")
])
def test_extract_info(user_agent, expected_os, expected_browser):
    os_info, browser_info = extract_info(user_agent)
    assert os_info == expected_os
    assert browser_info == expected_browser


@pytest.mark.parametrize("ip_address, mock_response, status_code, expected_location", [
    ("8.8.8.8", {"city": "San Francisco", "region": "California", "country": "US"}, 200,
     {"city": "San Francisco", "region": "California", "country": "US"}),  # Valid IP
    ("127.0.0.1", {"bogon": True}, 200, None),  # Bogon IP
    ("8.8.8.8", {}, 500, None),  # API failure
])
def test_get_location_from_ip(ip_address, mock_response, status_code, expected_location):
    with patch("httpx.get") as mock_get:
        mock_get.return_value.json.return_value = mock_response
        mock_get.return_value.status_code = status_code

        location = get_location_from_ip(ip_address)
        assert location == expected_location


@pytest.mark.parametrize("client_host, mock_location, expected_result", [
    (
        None,
        None,
        {
            "location": "Unknown Location",
            "device": "Unknown OS",
            "browser": "Unknown Browser",
            "ip_address": "Unknown IP"
        }
    ),
    (
        "127.0.0.1",
        None,
        {
            "location": "Loopback (localhost | 127.~.~.~)",
            "device": "Unknown OS",
            "browser": "Unknown Browser",
            "ip_address": "127.0.0.1"
        }
    ),
    (
        "10.0.0.1",
        None,
        {
            "location": "Private (class A | 10.~.~.~)",
            "device": "Unknown OS",
            "browser": "Unknown Browser",
            "ip_address": "10.0.0.1"
        }
    ),
    (
        # Before class B
        "172.15.0.1",
        {"city": "San Francisco", "region": "California", "country": "US"},
        {
            "location": "San Francisco, California, US",
            "device": "Unknown OS",
            "browser": "Unknown Browser",
            "ip_address": "172.15.0.1"
        }
    ),
    (
        "172.16.0.1",
        None,
        {
            "location": "Private (class B | 172.16.~.~ - 172.31.~.~)",
            "device": "Unknown OS",
            "browser": "Unknown Browser",
            "ip_address": "172.16.0.1"
        }
    ),
    (
        # After class B
        "172.32.0.1",
        {"city": "San Francisco", "region": "California", "country": "US"},
        {
            "location": "San Francisco, California, US",
            "device": "Unknown OS",
            "browser": "Unknown Browser",
            "ip_address": "172.32.0.1"
        }
    ),
    (
        "192.168.0.1",
        None,
        {
            "location": "Private (class C | 192.168.~.~)",
            "device": "Unknown OS",
            "browser": "Unknown Browser",
            "ip_address": "192.168.0.1"
        }
    ),
    (
        "8.8.8.8",
        {"city": "San Francisco", "region": "California", "country": "US"},
        {
            "location": "San Francisco, California, US",
            "device": "Unknown OS",
            "browser": "Unknown Browser",
            "ip_address": "8.8.8.8"
        }
    ),
])
def test_get_info_from_request(client_host, mock_location, expected_result):
    mock_request = None
    if client_host:
        mock_request = MagicMock()
        mock_request.headers = {"User-Agent": "Unknown User-Agent String"}
        mock_request.client.host = client_host

    with patch("app.core.utils.get_location_from_ip", return_value=mock_location):
        result = get_info_from_request(mock_request)
        assert result == expected_result


@pytest.mark.parametrize(
    "exists_return_value, open_side_effect, expected_result",
    [
        # Case 1: '/.dockerenv' exists, so it should return True
        (True, None, True),

        # Case 2: '/.dockerenv' does not exist, but '/proc/self/cgroup'
        # contains 'docker', so it should return True
        (False, "1:cpu:/docker", True),

        # Case 3: Neither '/.dockerenv' exists, nor 'docker'
        # is found in '/proc/self/cgroup', should return False
        (False, "1:cpu:/some_other_group", False),

        # Case 4: '/.dockerenv' does not exist, and '/proc/self/cgroup'
        # cannot be opened (FileNotFoundError), should return False
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


FakeNamedTuple = namedtuple("FakeNamedTuple", ["key"])
FakeDataInput = namedtuple(
    "FakeDataInput",
    ["system", "platform_name", "version", "release", "architecture", "processor",
     "cpu_count", "python_version", "is_docker", "uname", "details"]
)


@pytest.mark.parametrize(
    "fake_data_input, expected_machine_info",
    [
        # Case 1: Windows system
        (
            FakeDataInput(
                "Windows", "system-release-version-SP0", "10.0.18362", "10", "x86_64", "Intel", 4, "3.13.0", False,
                FakeNamedTuple("WinUnameDetails"),
                {"win32_ver": "WinVerDetailsTuple",
                    "win32_is_iot": False, "win32_edition": "Core"},
            ),
            {
                "platform": "system-release-version-SP0",
                "system": "Windows",
                "version": "10.0.18362",
                "release": "10",
                "architecture": "x86_64",
                "processor": "Intel",
                "cpu_count": 4,
                "python_version": "3.13.0",
                "is_docker": False,
                "uname": {"key": "WinUnameDetails"},
                "details": {"win32_ver": "WinVerDetailsTuple", "win32_is_iot": False, "win32_edition": "Core"},
            }
        ),

        # Case 2: Linux system
        (

            FakeDataInput(
                "Linux", "system-release-processor-with-glibc2.35", "#1 SMP <DATE>", "5.4.0-80",
                ('64bit', 'ELF'), "x86_64", 8, "3.13.0", True,
                FakeNamedTuple("LinuxUnameDetails"),
                {"freedesktop_os_release": "LinuxOSReleaseDetailsDict"},
            ),
            {
                "platform": "system-release-processor-with-glibc2.35",
                "system": "Linux",
                "version": "#1 SMP <DATE>",
                "release": "5.4.0-80",
                "architecture": ('64bit', 'ELF'),
                "processor": "x86_64",
                "cpu_count": 8,
                "python_version": "3.13.0",
                "is_docker": True,
                "uname": {"key": "LinuxUnameDetails"},
                "details": {"freedesktop_os_release": "LinuxOSReleaseDetailsDict"},
            }
        ),

        # Case 3: macOS system
        (
            FakeDataInput(
                "Darwin", "system-release-architecture", "19.6.0", "19.6.0", "x86_64", "Intel", 4, "3.8.5", False,
                FakeNamedTuple("MacUnameDetails"),
                {"mac_ver": "MacVerDetailsTuple"},
            ),
            {
                "platform": "system-release-architecture",
                "system": "Darwin",
                "version": "19.6.0",
                "release": "19.6.0",
                "architecture": "x86_64",
                "processor": "Intel",
                "cpu_count": 4,
                "python_version": "3.8.5",
                "is_docker": False,
                "uname": {"key": "MacUnameDetails"},
                "details": {"mac_ver": "MacVerDetailsTuple"},
            }
        ),

        # Case 4: iOS/iPadOS system
        (
            FakeDataInput(
                "iOS", "iOS-name", "version", "release", "architecture", "processor", 4, "3.8.5", False,
                FakeNamedTuple("iOSUnameDetails"),
                {"ios_ver": FakeNamedTuple("iOSVerDetails")},
            ),
            {
                "platform": "iOS-name",
                "system": "iOS",
                "version": "version",
                "release": "release",
                "architecture": "architecture",
                "processor": "processor",
                "cpu_count": 4,
                "python_version": "3.8.5",
                "is_docker": False,
                "uname": {"key": "iOSUnameDetails"},
                "details": {"ios_ver": {"key": "iOSVerDetails"}},
            }
        ),

        # Case 5: Android system
        (
            FakeDataInput(
                "Android", "Android-name", "version", "release", "architecture", "processor", 4, "3.8.5", False,
                FakeNamedTuple("AndroidUnameDetails"),
                {"android_ver": FakeNamedTuple("AndroidVerDetails")},
            ),
            {
                "platform": "Android-name",
                "system": "Android",
                "version": "version",
                "release": "release",
                "architecture": "architecture",
                "processor": "processor",
                "cpu_count": 4,
                "python_version": "3.8.5",
                "is_docker": False,
                "uname": {"key": "AndroidUnameDetails"},
                "details": {"android_ver": {"key": "AndroidVerDetails"}},
            }
        ),

        # Case 6: Unknown system
        (
            FakeDataInput(
                "unknown", "unknown", "unknown", "unknown", "todo", "YoLo", 69420, "3.8.5", False,
                FakeNamedTuple("UnknownUnameDetails"),
                {"platform": "Unknown OS"},
            ),
            {
                "platform": "unknown",
                "system": "unknown",
                "version": "unknown",
                "release": "unknown",
                "architecture": "todo",
                "processor": "YoLo",
                "cpu_count": 69420,
                "python_version": "3.8.5",
                "is_docker": False,
                "uname": {"key": "UnknownUnameDetails"},
                "details": {"platform": "Unknown OS"},
            }
        )
    ]
)
def test_get_machine_info(fake_data_input, expected_machine_info):
    # Mocking the platform and os methods
    with patch("platform.platform", return_value=fake_data_input.platform_name), \
            patch("platform.system", return_value=fake_data_input.system), \
            patch("platform.version", return_value=fake_data_input.version), \
            patch("platform.release", return_value=fake_data_input.release), \
            patch("platform.machine", return_value=fake_data_input.architecture), \
            patch("platform.processor", return_value=fake_data_input.processor), \
            patch("platform.uname", return_value=fake_data_input.uname), \
            patch("os.cpu_count", return_value=fake_data_input.cpu_count), \
            patch("platform.python_version", return_value=fake_data_input.python_version), \
            patch("app.core.utils.detect_docker", return_value=fake_data_input.is_docker):

        # Mocking system-specific details
        match fake_data_input.system:
            case "Windows":
                with patch("platform.win32_ver", return_value=fake_data_input.details["win32_ver"]), \
                        patch("platform.win32_is_iot", return_value=fake_data_input.details["win32_is_iot"]), \
                        patch("platform.win32_edition", return_value=fake_data_input.details["win32_edition"]):
                    result = get_machine_info()
                    assert result == expected_machine_info
            case "Linux":
                with patch(
                    "platform.freedesktop_os_release",
                    return_value=fake_data_input.details["freedesktop_os_release"]
                ):
                    result = get_machine_info()
                    assert result == expected_machine_info
            case "Darwin":
                with patch("platform.mac_ver", return_value=fake_data_input.details["mac_ver"]):
                    result = get_machine_info()
                    assert result == expected_machine_info
            case "iOS":
                with patch("platform.ios_ver", return_value=fake_data_input.details["ios_ver"]):
                    result = get_machine_info()
                    assert result == expected_machine_info
            case "Android":
                with patch("platform.android_ver", return_value=fake_data_input.details["android_ver"]):
                    result = get_machine_info()
                    assert result == expected_machine_info
            case _:
                result = get_machine_info()
                assert result == expected_machine_info


@pytest.mark.parametrize("mock_output, expected_result", [
    (
        "abc123\n2024-11-19\nJohn Doe\njohn.doe@example.com\nInitial commit\nAdded README",
        {
            "hash": "abc123",
            "date": "2024-11-19",
            "author_name": "John Doe",
            "author_email": "john.doe@example.com",
            "subject": "Initial commit",
            "body": "Added README"
        }
    ),
    (
        "",  # Empty output
        {
            "hash": "",
            "date": "",
            "author_name": "",
            "author_email": "",
            "subject": "",
            "body": ""
        }
    )
])
def test_get_latest_commit_info(mock_output, expected_result):
    with patch("subprocess.check_output", return_value=mock_output):
        result = get_latest_commit_info()
        assert result == expected_result


def test_get_latest_commit_info_error():
    with patch("subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "git")):
        result = get_latest_commit_info()
        assert result is None


@pytest.mark.parametrize("input_details, expected_output", [
    # Standard Case: Proper key-value pairs
    (
        "Fetch URL: git@github.com:user/repo.git\n"
        "Push URL: git@github.com:user/repo.git",
        {
            "Fetch URL": "git@github.com:user/repo.git",
            "Push URL": "git@github.com:user/repo.git"
        }
    ),
    # Case with multiline value
    (
        "Fetch URL:\n"
        "git@github.com:user/repo.git\n"
        "Push URL: git@github.com:user/repo.git",
        {
            "Fetch URL": "git@github.com:user/repo.git",
            "Push URL": "git@github.com:user/repo.git"
        }
    ),
    # Empty Input
    (
        "",
        {}
    ),
    # Case with malformed input (no colon)
    (
        "Malformed Line Without Colon\n"
        "Fetch URL: git@github.com:user/repo.git",
        {
            "Fetch URL": "git@github.com:user/repo.git"
        }
    ),
    # Case with trailing colon and no subsequent line
    (
        "Fetch URL:\n"
        "Push URL: git@github.com:user/repo.git",
        {
            "Fetch URL": "<unknown>",
            "Push URL": "git@github.com:user/repo.git"
        }
    )
])
def test_parse_remote_details(input_details, expected_output):
    result = parse_remote_details(input_details)
    assert result == expected_output


@pytest.mark.parametrize("mock_outputs, expected_result", [
    (
        {
            "remote_url": "git@github.com:user/repo.git",
            "branch_name": "main",
            "remote_details": "Fetch URL: git@github.com:user/repo.git\nPush URL: git@github.com:user/repo.git",
            "push_url": "git@github.com:user/repo.git"
        },
        {
            "owner": "user",
            "repo_name": "repo",
            "branch_name": "",
            "remote_url": "git@github.com:user/repo.git",
            "fetch_url": "git@github.com:user/repo.git",
            "push_url": "git@github.com:user/repo.git",
            "remote_details": {}
        }
    ),
    (
        {  # Invalid remote URL format
            "remote_url": "invalid-url",
            "branch_name": "main",
            "remote_details": "",
            "push_url": ""
        },
        {
            "owner": "<unknown>",
            "repo_name": "<unknown>",
            "branch_name": "",
            "remote_url": "invalid-url",
            "fetch_url": "invalid-url",
            "push_url": "invalid-url",
            "remote_details": {}
        }
    )
])
def test_get_repository_info(mock_outputs, expected_result):
    with patch("subprocess.check_output") as mock_check_output:
        def side_effect(cmd, text):  # pylint: disable=unused-argument
            if "remote.origin.url" in cmd:
                return mock_outputs["remote_url"]
            if "rev-parse --abbrev-ref" in cmd:
                return mock_outputs["branch_name"]
            if "remote show origin" in cmd:
                return mock_outputs["remote_details"]
            if "remote.origin.pushurl" in cmd:
                return mock_outputs["push_url"]
            return ""

        mock_check_output.side_effect = side_effect

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = mock_outputs.get("push_url", "")

            result = get_repository_info()

            # Handle remote_details correctly
            if isinstance(result["remote_details"], str):
                result["remote_details"] = dict(
                    line.split(": ", 1) for line in result["remote_details"].splitlines() if ": " in line
                )
            assert result == expected_result


def test_get_repository_info_error():
    with patch("subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "git")):
        result = get_repository_info()
        assert result is None
