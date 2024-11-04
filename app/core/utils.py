"""
This module contains miscellaneous utilities such as a generator for random strings,
validators for different types of data (e.g. email addresses), functions to get information
from a FastAPI Request object, a function to generate a profile picture from a string,
functions to get information about a request, and a function to convert a FastAPI
route to a URL.


@file: ./app/core/utils.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""
from io import BytesIO
import json
from logging import Logger
import os
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


def validate_email(email: str) -> str:
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


# ----- UTILS ----- #

def pprint(obj: object, logging: bool = False) -> None:
    if logging:
        logger.debug("\n%s", json.dumps(obj, indent=4))
    else:
        print(json.dumps(obj, indent=4))


def not_found_page() -> Response:
    """
    Returns an HTTP 404 response with the content of the 404.html template.

    :return Response: The 404 response.
    """
    with open("./templates/html/404.html", "r", encoding="utf-8") as f:
        template = Template(f.read(), undefined=DebugUndefined)
    context = {
        "FRONTEND_URL": settings.FRONTEND_URL,
    }
    html = template.render(context)
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
