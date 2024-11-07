"""
This module provides OAuth integration using Authlib with Starlette.

It handles OAuth client setup and token management, including fetching and updating tokens.

@file: ./app/core/oauth.py
@date: 10/12/2024
@author: LordLumineer (https://github.com/LordLumineer)
"""

from authlib.integrations.starlette_client import OAuth

from app.core.config import settings
from app.core.object.oauth import (fetch_token, update_token)


oauth = OAuth(
    fetch_token=fetch_token,
    update_token=update_token
)

if settings.API_CLIENT_ID_GOOGLE and settings.API_CLIENT_SECRET_GOOGLE:
    oauth.register(
        'google',
        client_id=settings.API_CLIENT_ID_GOOGLE,
        client_secret=settings.API_CLIENT_SECRET_GOOGLE,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        access_token_params=None,
        authorize_params={'access_type': 'offline'},
        client_kwargs={'scope': 'openid profile email',
                       'code_challenge_method': 'S256'}
    )

if settings.API_CLIENT_ID_GITHUB and settings.API_CLIENT_SECRET_GITHUB:
    oauth.register(
        'github',
        client_id=settings.API_CLIENT_ID_GITHUB,
        client_secret=settings.API_CLIENT_SECRET_GITHUB,
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        server_metadata_url='https://token.actions.githubusercontent.com/.well-known/openid-configuration',
        userinfo_endpoint='https://api.github.com/user',
        client_kwargs={'scope': 'openid user:email read:user',
                       'code_challenge_method': 'S256'},
    )

if settings.API_CLIENT_ID_TWITCH and settings.API_CLIENT_SECRET_TWITCH:
    TWITCH_CLAIMS = str({
        "id_token": {
            "email": None,
            "email_verified": None,
            "preferred_username": None,
        },
        "userinfo": {
            "email": None,
            "email_verified": None,
            "picture": None,
            "preferred_username": None,
            "updated_at": None,
        },
    }).replace('None', 'null').replace("'", '"')
    oauth.register(
        'twitch',
        client_id=settings.API_CLIENT_ID_TWITCH,
        client_secret=settings.API_CLIENT_SECRET_TWITCH,
        server_metadata_url='https://id.twitch.tv/oauth2/.well-known/openid-configuration',
        authorize_params={'claims': TWITCH_CLAIMS},
        access_token_params={'client_id': settings.API_CLIENT_ID_TWITCH,
                             'client_secret': settings.API_CLIENT_SECRET_TWITCH},
        client_kwargs={'scope': 'openid user:read:email',
                       'code_challenge_method': 'S256'},
    )

if settings.API_CLIENT_ID_DISCORD and settings.API_CLIENT_SECRET_DISCORD:
    oauth.register(
        'discord',
        client_id=settings.API_CLIENT_ID_DISCORD,
        client_secret=settings.API_CLIENT_SECRET_DISCORD,
        access_token_url='https://discord.com/api/oauth2/token',
        access_token_params=None,
        authorize_url='https://discord.com/oauth2/authorize',
        authorize_params=None,
        api_base_url='https://discord.com/api',
        userinfo_endpoint='https://discord.com/api/users/@me',
        client_kwargs={'scope': 'identify email',
                       'code_challenge_method': 'S256'},
    )

# NOTE: Not supported yet
# oauth.register(
#     'twitter',
#     client_id=settings.API_CLIENT_ID_TWITTER,
#     client_secret=settings.API_CLIENT_SECRET_TWITTER,
#     # server_metadata_url='.well-known/openid-configuration',
#     access_token_url='https://api.x.com/2/oauth2/token',
#     access_token_params=None,
#     authorize_url='https://twitter.com/i/oauth2/authorize',
#     authorize_params=None,
#     api_base_url='https://api.x.com',
#     userinfo_endpoint='https://api.twitter.com/2/users/me',
#     client_kwargs={'scope': 'offline.access users.read tweet.read',
#                 'code_challenge_method': 'S256'}
# )

# NOTE: Not supported yet
# if settings.API_CLIENT_ID_REDDIT and settings.API_CLIENT_SECRET_REDDIT:
#     oauth.register(
#         'reddit',
#         client_id=settings.API_CLIENT_ID_REDDIT,
#         client_secret=settings.API_CLIENT_SECRET_REDDIT,
#         # server_metadata_url='.well-known/openid-configuration',
#         access_token_url='https://www.reddit.com/api/v1/access_token',
#         access_token_params=None,
#         authorize_url='https://www.reddit.com/api/v1/authorize',
#         authorize_params=None,
#         api_base_url='https://www.reddit.com',
#         userinfo_endpoint='https://www.reddit.com/api/v1/me',
#         client_kwargs={'scope': 'identity',
#                     'code_challenge_method': 'S256'}
#     )

# NOTE: Not supported yet
# if settings.API_CLIENT_SECRET_MICROSOFT and settings.API_CLIENT_SECRET_MICROSOFT:
# oauth.register(
#     'microsoft',
#     client_id=settings.API_CLIENT_SECRET_MICROSOFT,
#     client_secret=settings.API_CLIENT_SECRET_MICROSOFT,
#     server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
#     client_kwargs={'scope': 'openid profile email offline_access',
#                    'code_challenge_method': 'S256'}
# )

oauth_clients_names = list(oauth._clients)  # pylint: disable=protected-access
