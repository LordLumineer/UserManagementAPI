"""
This module contains the logic to interact with GitHub's OAuth2 API.

It provides functions to extract the relevant information from the user info
returned by GitHub and to get the user's profile picture.
"""


def get_acc_info(user_info: dict) -> dict:
    """
    Extract the relevant information from the user info provided by GitHub.

    :param dict user_info: The user information returned by GitHub.
    :return dict: A dictionary containing the following information:
        - provider: The name of the OAuth provider.
        - id: The user ID.
        - username: The username.
        - display_name: The display name.
        - emails: A list of emails associated with the user. The primary email is the first item.
        - picture_url: The URL of the user's profile picture.
    """
    emails = [
        email for email in user_info["emails"]
        if email["verified"] and email["email"].split("@")[-1] != "users.noreply.github.com"
    ]
    primary_emails = [
        email['email'] for email in emails if email["primary"]]
    other_emails = [
        email['email'] for email in emails if not email["primary"]]
    return {
        "provider": "github",
        "id": str(user_info["id"]),
        "username": user_info["login"].lower().replace(" ", "_"),
        "display_name": user_info["login"],
        "emails": primary_emails + other_emails,
        "picture_url": user_info["avatar_url"] + ".png"
    }
