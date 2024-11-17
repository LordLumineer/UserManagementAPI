"""
This module contains miscellaneous utilities such as a generator for random strings,
validators for different types of data (e.g. email addresses), functions to get information
from a FastAPI Request object, a function to generate a profile picture from a string,
functions to get information about a request, and a function to convert a FastAPI
route to a URL.
"""
from datetime import datetime, timezone
from io import BytesIO
import os
import platform
import subprocess
import time
import random
import re
import string
import uuid
from email_validator import EmailNotValidError
from email_validator import validate_email as email_validation
from fastapi import HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from PIL import Image, ImageDraw, ImageFont
import httpx
from jinja2 import DebugUndefined, Template

from app.core.config import logger, settings


def validate_username(username: str) -> str:
    """
    Validates the provided username.

    :param str username: The username to validate.
    :return str: The validated username.
    :raises HTTPException: If the username is invalid.
    """
    username_pattern = r"^[a-z0-9_]{5,}$"
    if bool(re.match(username_pattern, username)):
        return username
    if settings.ENVIRONMENT == "local":
        logger.warning("Invalid username format: %s", username)
        return username
    raise HTTPException(
        status_code=400,
        detail="""
        Username must be at least 5 characters long, contain only lowercase letters, numbers, and underscores.
        """
    )


def validate_email(email: str, raise_error: bool = True) -> str:
    """
    Validates the provided email address.

    :param str email: The email address to validate.
    :return str: The validated email address.
    :raises HTTPException: If the email address is invalid.
    """
    try:
        if email == "admin@example.com":
            return email
        email_info = email_validation(email, check_deliverability=True)
    except EmailNotValidError as e:
        if not raise_error:
            logger.debug("Invalid email format: %s", email)
            return False
        if settings.ENVIRONMENT == "local":
            logger.warning("Invalid email format: %s", email)
            return email
        raise HTTPException(
            status_code=400, detail="Email is not valid. " + str(e)) from e
    return email_info.normalized


def validate_password(password: str) -> str:
    """
    Validates the provided password.

    :param str password: The password to validate.
    :return str: The validated password.
    :raises HTTPException: If the password is invalid.
    """
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{10,}$"
    if bool(re.match(regex, password)):
        return password
    if settings.ENVIRONMENT == "local":
        logger.warning("Invalid password format: %s", password)
        return password
    raise HTTPException(
        status_code=400,
        detail="Password must be at least 10 characters long, contain at least one uppercase letter, \
            one lowercase letter, one number, and one special character (@$!%*#?&)."
    )


# ----- GENERATORS ----- #


def generate_random_letters(length: int, seed: int | str = None) -> str:
    """
    Generates a string of random letters of a given length.

    :param length: Length of the random letter string.
    :param seed: Optional seed for reproducibility. Defaults to current time.
    :return: A string of random letters.
    """
    if seed is None:
        seed = int(time.time())  # Use current time if no seed is provided
    random.seed(seed+str(int(time.time())))

    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))


def generate_random_digits(length: int, seed: int | str = None) -> str:
    """
    Generates a string of random digits of a given length.

    :param length: Length of the random digit string.
    :param seed: Optional seed for reproducibility. Defaults to current time.
    :return: A string of random digits.
    """
    if seed is None:
        seed = int(time.time())  # Use current time if no seed is provided
    random.seed(seed+str(int(time.time())))
    return ''.join(str(random.randint(0, 9)) for _ in range(length))


def generate_uuid() -> str:
    """
    Generates a random UUID.

    :return: A random UUID.
    """
    return str(uuid.uuid4())


def generate_timestamp() -> int:
    """
    Generates a timestamp representing the current time.

    :return: An integer timestamp.
    """
    return int(time.time())


def extract_initials_from_text(text: str) -> str:
    """
    Extracts the initials from a given string.

    :param str text: The string from which to extract the initials.
    :return str: The extracted initials.
    """
    result = []
    capitalize_next = True
    for char in text:
        if char.isalpha():
            if capitalize_next:
                result.append(char.upper())
                capitalize_next = False
            else:
                capitalize_next = False
        elif char.isdigit() or char == '_' or char == ' ':
            capitalize_next = True
    return ''.join(result)


async def generate_profile_picture(letters: str = 'OS') -> Response:
    """
    Generates a PNG image of a given size with the provided letters centered horizontally and vertically.

    :param str letters: The letters to render in the image. Defaults to 'OS'.
    :return Response: The generated image as a PNG response.
    """
    img_size = 100
    max_dim = img_size * 0.8  # 90% of the image size
    img = Image.new('RGB', (img_size, img_size), color='gray')
    draw = ImageDraw.Draw(img)

    font_size = 150
    font = ImageFont.truetype("arial.ttf", font_size)

    while True:
        bbox = draw.textbbox((0, 0), letters, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        if text_width <= max_dim and text_height <= max_dim:
            break
        font_size -= 1
        if font_size <= 0:
            break
        font = ImageFont.truetype("arial.ttf", font_size)

    bbox = draw.textbbox((0, 0), letters, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    position = ((img_size - text_width) // 2,
                (((img_size - text_height) // 2) - (text_height / 4)))

    draw.text(position, letters, fill="white", font=font)

    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)

    return Response(content=img_io.getvalue(), media_type="image/png")


def custom_generate_unique_id(route: APIRoute) -> str:
    """Generate a unique ID for a route by combining its first tag with its name."""
    return f"{route.tags[0]}-{route.name}"


def render_html_template(html_content: str, context: dict = None) -> str:
    """
    Renders an HTML template with the given content and context.

    :param str html_content: The HTML content to be rendered.
    :param dict context: A dictionary of context variables to be used in rendering the template.
    :return str: The rendered HTML as a string.
    """
    base_context = {
        "PROJECT_NAME": settings.PROJECT_NAME,
        "FRONTEND_URL": settings.FRONTEND_URL,
        "COPYRIGHT_YEAR": datetime.now(timezone.utc).year,
        "PRIVACY_URL": f"{settings.FRONTEND_URL}/privacy",
        "TERMS_URL": f"{settings.FRONTEND_URL}/terms",
        "SUPPORT_EMAIL": settings.CONTACT_EMAIL,
        # FIXME:  f"{settings.BASE_URL}{settings.API_STR}/static/logo.png",
        "LOGO_URL": "https://picsum.photos/600/300",
        "BASE_URL": settings.BASE_URL,
        "API_STR": settings.API_STR,
    }
    base_context.update(context or {})
    return Template(
        html_content, undefined=DebugUndefined).render(base_context)


# ----- UTILS ----- #


def not_found_page() -> Response:
    """
    Returns an HTTP 404 response with the content of the 404.html template.

    :return Response: The 404 response.
    """
    with open("./templates/html/404.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    html = render_html_template(html_content)
    return HTMLResponse(content=html, status_code=404)


def remove_file(file_path: str):
    """
    Removes the file at the given path if it exists.

    :param str file_path: The path to the file to remove.
    """
    if os.path.exists(file_path):
        os.remove(file_path)


# ----- REQUEST ----- #


def extract_info(user_agent):
    """
    Extracts OS and browser information from the given user agent string.

    :param str user_agent: The user agent string to parse.
    :return tuple: A tuple containing the OS information and browser information as strings.
    """
    os_info = "Unknown OS"
    browser_info = "Unknown Browser"

    os_match = re.search(r'\((.*?)\)', user_agent)
    if os_match:
        os_info = os_match.group(1)

    if "Firefox" in user_agent:
        browser_info = "Firefox"
    elif "Edg" in user_agent:
        browser_info = "Edge"
    elif "Chrome" in user_agent and "Safari" in user_agent:
        browser_info = "Chrome"
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        browser_info = "Safari"
    elif "Opera" in user_agent:
        browser_info = "Opera"
    elif "Trident" in user_agent:
        browser_info = "Internet Explorer"

    return os_info, browser_info


def get_location_from_ip(ip_address):
    """
    Gets the location information from an IP address using the ipinfo.io API.

    :param str ip_address: The IP address to lookup.
    :return dict: A dictionary containing the location information. None if the lookup fails.
    """
    response = httpx.get(f"http://ipinfo.io/{ip_address}/json", timeout=5)
    data = response.json()
    if data.get("bogon"):
        return None
    if response.status_code == 200:
        return data
    return None


def get_info_from_request(request: Request = None):
    """
    Gets the location, device type, browser type and IP address from the given request.

    :param Request request: The request object to extract the information from. Defaults to None.
    :return tuple: A tuple containing the location, device type, browser type and IP address as strings.
    """
    if not request:
        return "Unknown Location", "Unknown Device", "Unknown Browser", "Unknown IP"
    device, browser = extract_info(request.headers["User-Agent"])
    location = "Unknown Location"
    client_host = request.client.host
    if client_host.startswith("127."):
        location = "Loopback (localhost | 127.~.~.~)"
    elif client_host.startswith("10."):
        location = "Private (class A | 10.~.~.~)"
    elif client_host.startswith("172.") and 16 <= client_host.split(".")[1] <= "31":
        location = "Private (class B | 172.16.~.~ - 172.31.~.~)"
    elif client_host.startswith("192.168."):
        location = "Private (class C | 192.168.~.~ - 192.168.~.~)"
    else:
        data = get_location_from_ip(client_host)
        if data:
            location = f"{data['city']}, {data['region']}, {data['country']}"
    return location, device, browser, request.client.host


def detect_docker():
    """Detects if the code is currently running inside a docker container.

    Two methods are used to detect if the code is running inside a docker container:
    1. Checking for the existence of the file '/.dockerenv'.
    2. Checking for the string 'docker' in the file '/proc/self/cgroup'.

    If either of these methods returns True, then the function returns True.
    Otherwise, it returns False.
    """
    if os.path.exists('/.dockerenv'):
        return True
    try:
        with open('/proc/self/cgroup', 'r', encoding='utf-8') as f:
            if 'docker' in f.read():
                return True
    except FileNotFoundError:
        pass
    return False

def get_machine_info():
    """
    Gets the information about the machine the application is running on.

    The function collects the following information:

    - The platform name.
    - The system name.
    - The version of the system.
    - The release of the system.
    - The architecture of the system.
    - The processor of the system.
    - The number of CPUs of the system.
    - The Python version.
    - Whether the code is running inside a Docker container.

    The function also collects the following information based on the system:

    - For Windows: The Windows version, whether it is an IoT version, and the edition.
    - For Linux: The freedesktop.org OS release.
    - For Darwin (macOS): The macOS version.
    - For iOS and iPadOS: The iOS version.
    - For Android: The Android version.
    - For other systems: The libc version.

    Returns a dictionary containing the collected information.
    """
    machine = {
        "platform": platform.platform(),
        "system": platform.system(),
        "version": platform.version(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
        "is_docker": detect_docker()
    }
    match machine["system"]:
        # case "Java":
        #     machine["details"] = {
        #         "java_ver": platform.java_ver()
        #     }
        case "Windows":
            machine["details"] = {
                "win32_ver": platform.win32_ver(),
                "win32_is_iot": platform.win32_is_iot(),
                "win32_edition": platform.win32_edition(),
            }
        case "Linux":
            machine["details"] = {
                "freedesktop_os_release": platform.freedesktop_os_release()
            }
        case "Darwin":
            machine["details"] = {
                "mac_ver": platform.mac_ver()
            }
        case "iOS" | "iPadOS":
            machine["details"] = {
                "ios_ver": platform.ios_ver()  # pylint: disable=E1101
            }
        case "Android":
            machine["details"] = {
                "android_ver": platform.android_ver()  # pylint: disable=E1101
            }
        case _:
            machine["details"] = {
                "platform": "Unknown OS",
                "libc_ver": platform.libc_ver()
            }
    return machine

def get_latest_commit_info():
    """
    Retrieves information about the latest commit in the repository.

    The information is obtained via the 'git log' command with the following format:
    '%H%n%cd%n%an%n%ae%n%s%n%b'. This format returns the commit hash, date, author name,
    author email, commit subject, and commit body.

    If an error occurs while running the command, the function returns None.

    :return dict: A dictionary containing the commit information.
    """
    try:
        # Get detailed information of the latest commit
        commit_info = subprocess.check_output(
            ['git', 'log', '-1', '--pretty=format:%H%n%cd%n%an%n%ae%n%s%n%b'],
            text=True
        ).strip()

        # Split the output into parts and handle missing values
        parts = commit_info.split('\n', 5)
        while len(parts) < 6:
            parts.append('')

        commit_hash, commit_date, author_name, author_email, subject, body = parts

        return {
            "hash": commit_hash,
            "date": commit_date,
            "author_name": author_name,
            "author_email": author_email,
            "subject": subject,
            "body": body.strip()
        }

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return None

def get_repository_info():
    """
    Retrieves information about the Git repository.

    The information is obtained via the following git commands:
    1. 'git config --get remote.origin.url' to get the remote URL.
    2. 'git rev-parse --abbrev-ref HEAD' to get the current branch name.
    3. 'git remote show origin' to get detailed information about the remote.
    4. 'git config --get remote.origin.pushurl' to get the push URL.

    If an error occurs while running the commands, the function returns None.

    :return dict: A dictionary containing the repository information.
    """
    def parse_remote_details(remote_details):
        details_dict = {}
        lines = remote_details.split('\n')
        for idx, line in enumerate(lines):
            if ':' in line:
                if line.strip().endswith(':'):
                    details_dict[line[:-1].strip()] = lines[idx+1].strip()
                else:
                    key, value = line.split(':', 1)
                    details_dict[key.strip()] = value.strip()
        return details_dict
    try:
        # Get the remote URL
        remote_url = subprocess.check_output(
            ['git', 'config', '--get', 'remote.origin.url'],
            text=True
        ).strip()
        # Extract repository owner and name from the remote URL
        match = re.search(r'[:/]([\w-]+)/([\w-]+)(\.git)?$', remote_url)
        if match:
            owner = match.group(1)
            repo_name = match.group(2)
        else:
            owner, repo_name = '<unknown>', '<unknown>'
        # Get the current branch name
        branch_name = subprocess.check_output(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            text=True
        ).strip()
        # Get detailed information about the remote
        remote_details = subprocess.check_output(
            ['git', 'remote', 'show', 'origin'],
            text=True
        ).strip()
        remote_details = parse_remote_details(remote_details)
        # Get fetch and push URLs
        fetch_url = subprocess.check_output(
            ['git', 'config', '--get', 'remote.origin.url'],
            text=True
        ).strip()
        push_url = subprocess.check_output(
            ['git', 'config', '--get', 'remote.origin.pushurl'],
            text=True
        ).strip() if subprocess.run(['git', 'config', '--get', 'remote.origin.pushurl'], text=True, capture_output=True).stdout else fetch_url
        return {
            "owner": owner,
            "repo_name": repo_name,
            "branch_name": branch_name,
            "remote_url": remote_url,
            "fetch_url": fetch_url,
            "push_url": push_url,
            "remote_details": remote_details
        }
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
        return None