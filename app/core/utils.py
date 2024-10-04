from io import BytesIO
import os
import time
import random
import re
import string
from email_validator import EmailNotValidError
from email_validator import validate_email as email_validation
from fastapi import HTTPException, Response
from PIL import Image, ImageDraw, ImageFont

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
        status_code=400, detail="Username must be at least 5 characters long, contain only lowercase letters, numbers, and underscores.")


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
    random.seed(seed)

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
    random.seed(seed)
    return ''.join(str(random.randint(0, 9)) for _ in range(length))


def extract_initials_from_text(text: str) -> str:
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


def remove_file(file_path: str):
    """
    Removes the file at the given path if it exists.

    :param str file_path: The path to the file to remove.
    """
    if os.path.exists(file_path):
        os.remove(file_path)


# import uuid

# def generate_uuid() -> str:
#     """
#     Generates a random UUID (Universally Unique Identifier).

#     :return: A string containing a random UUID.
#     """
#     return str(uuid.uuid4())

# from datetime import datetime


# def generate_timestamp() -> int:
#     """
#     Generates the current timestamp in milliseconds.

#     :return: The current timestamp as an integer in milliseconds.
#     """
#     return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
