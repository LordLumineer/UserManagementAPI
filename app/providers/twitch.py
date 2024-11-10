"""
This module contains the logic to interact with Twitch's OAuth2 API.

It provides functions to extract the relevant information from the user info
returned by Twitch and to get the user's profile picture.
"""


def get_acc_info(user_info: dict) -> dict:
    """
    Extract the relevant information from the user info provided by Twitch.

    :param dict user_info: The user information returned by Twitch.
    :return dict: A dictionary containing the following information:
        - provider: The name of the OAuth provider.
        - id: The user ID.
        - username: The username.
        - display_name: The display name.
        - emails: A list of emails associated with the user.
        - picture_url: The URL of the user's profile picture.
    """
    return {
        "provider": "twitch",
        "id": user_info["sub"],
        "username": user_info["preferred_username"].lower().replace(" ", "_"),
        "display_name": user_info["preferred_username"],
        "emails": [user_info["email"]],
        "picture_url": user_info["picture"]
    }