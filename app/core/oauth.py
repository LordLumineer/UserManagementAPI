from authlib.integrations.starlette_client import OAuth
from sqlalchemy.orm import Session

from app.core.db import get_db

# def fetch_token(name, request):
    
    
#     if name in OAUTH1_SERVICES:
#         model = OAuth1Token
#     else:
#         model = OAuth2Token

#     token = model.find(
#         name=name,
#         user=request.user
#     )
#     return token.to_token()

oauth = OAuth()

oauth.register(
    'google',
    client_id= '{{ your-google-client-id }}',
    client_secret= '{{ your-google-client-secret }}',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)

oauth.register(
    name='github',
    client_id='{{ your-github-client-id }}',
    client_secret='{{ your-github-client-secret }}',
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)