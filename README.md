# UserManagementAPI_DEV

Labels....
logo....

## Table of Contents

- [UserManagementAPI\_DEV](#usermanagementapi_dev)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Features](#features)
    - [Rate Limiter](#rate-limiter)
    - [Feature Flags](#feature-flags)
    - [Attribute Based Access Control (ABAC)](#attribute-based-access-control-abac)
    - [Database](#database)
    - [Local Users](#local-users)
    - [File Uploads](#file-uploads)
    - [3rd Party login](#3rd-party-login)
      - [Supported Providers](#supported-providers)
  - [Deployment](#deployment)
    - [Environment Variables](#environment-variables)
    - [Docker](#docker)
    - [Local](#local)
      - [Requirements](#requirements)
  - [Usage](#usage)
  - [Development](#development)
    - [Testing](#testing)
      - [Testing Requirements](#testing-requirements)
      - [Coverage](#coverage)
      - [Linting](#linting)
      - [Load Testing](#load-testing)
      - [Documentation](#documentation)
    - [Useful Commands](#useful-commands)
  - [Credits](#credits)
    - [Third-Party Libraries](#third-party-libraries)
  - [Note from the Creator](#note-from-the-creator)
  - [License](#license)
  - [Changelog](#changelog)

## Introduction

## Features

### Rate Limiter

**WARNING**: Do not reduce the amount too much as some edge cases cascade in multiple requests.
E.G:`http://localhost/api/oauth/<provider>?redirect_uri=http://localhost/interactive-docs`

```bash
"GET /api/oauth/<provider> HTTP/1.1"                                                      302 Found
"GET /api/oauth/<provider>/callback?code=<code>&scope=<scopes>&state=<state> HTTP/1.1"    200 OK
"GET /interactive-docs HTTP/1.1"                                                          307 Temporary Redirect
"GET /signin HTTP/1.1"                                                                    200 OK
"GET /api/auth/token/validate HTTP/1.1"                                                   200 OK
"GET /redirect_uri HTTP/1.1"                                                              307 Temporary Redirect
"GET /interactive-docs?token=<TOKEN> HTTP/1.1"                                            307 Temporary Redirect
"GET /docs HTTP/1.1"                                                                      200 OK
"GET /docs HTTP/1.1"                                                                      200 OK
"GET /openapi.json HTTP/1.1"                                                              200 OK
```

### Feature Flags

### Attribute Based Access Control (ABAC)

### Database

### Local Users

### File Uploads

### 3rd Party login

User API uses the `email` linked to the third party account to create / link with a local account.

You can login with a 3rd party account using the `/oauth/{3rd-party-provider}` endpoint.

- If the 3rd party account is already linked with a local account, you will get the login response (the same as the `/login` endpoint with `username or email` and `password`).
- If the 3rd party account is not linked with a local account, and find a local account with the same email and the email has been verified for the local account (and 3rd party account), it will link the 3rd party account with the local account and complete the login.
- If the emails aren't verified, it will raise an error.
- If the 3rd party account is not linked with a local account, it will create a new local account and link it with the 3rd party account and complete the login.

If you have a 3rd party account that you want to link with a local account but the email doesn't match with the email registered with the local account, you can use the `/oauth/{3rd-party-provider}/link` endpoint while being logged in with the local account (Header: `Authorization: Bearer {token}`).

- If the 3rd party account is not already linked with a local account, it will link it with the local account.
- If the 3rd party account is already linked with a local account that isn't yours, you will receive an error (based on `local_account.uuid`).
- If the 3rd party account is already linked with a local account that is yours, you will also receive an error (based on `3rd_party_account.id`).

If the local account doesn't have a profile picture, the picture from the 3rd party account will be used.

For more information you can read the [associated code](./app/api/routes/oauth.py#L34-L275).

#### Supported Providers

- Bluesky / AtProto *(NOT SUPPORTED YET)*
- Discord
- GitHub
- Google
- Reddit *(NOT SUPPORTED YET)*
- Twitch
- Twitter / X *(NOT SUPPORTED YET)*

***WARNING:*** *Twitter integration is limited, you can link a twitter account to a local one with no issues then login with it, however first time login will fail.*
*furthermore it is limited by the Twitter API own limitations*

## Deployment

### Environment Variables

- **URL**
  - `BASE_URL`: The base URL of the API. It is used for the rendering of the emails, and also for the files / profile picture links when the data are requested.
  - `API_STR`: The API prefix. Used in the same way as `BASE_URL`.
  - `FRONTEND_URL`: The URL of the frontend. Used in the email rendering. And for the pages like `/terms` and `/privacy`.
- **LOG**
  - `LOG_LEVEL`: The log level of the console. By default it is set to `INFO`, it can be set to `TRACE` (Not recommended), `DEBUG`, `INFO`, `SUCCESS`, `WARNING`, `ERROR` or `CRITICAL`.
  - `LOG_FILE_ENABLED`: If the log file is enabled. By default it is set to `False`, it can be set to `True`.
  - `LOG_FILE_LEVEL`: The log level of the log file. By default it is set to `WARNING`.
  - `LOG_FILE_ROTATION`: The log file rotation in hours. By default it is set to `24`. For more granular control, you can use set it with a string like `'100 MB'` (ref. [loguru docs](https://loguru.readthedocs.io/en/stable/api/logger.html#file)).
  - `LOG_FILE_RETENTION`: The log file retention in days. By default it is set to `30`. It can also be set with a string like `'100 MB'` (ref. [loguru docs](https://loguru.readthedocs.io/en/stable/api/logger.html#file)).
- **JWT**
  - `JWT_SECRET_KEY`: The secret key used to sign the JWT. **IMPORTANT**: for security reason it has to be set.
  - `JWT_EXP`: The expiration time of the JWT in minutes. By default it is set to `30`.
- **OTP** (One-time password)
  - `OTP_LENGTH`: The length of the one-time password (OTP). By default it is set to `6`.
  - `OTP_AUTHENTICATOR_INTERVAL`: The interval (in seconds) of the one-time password (OTP) for authenticator apps (such as Google Authenticator, Authy, and Microsoft Authenticator). By default it is set to `30`.
  - `OTP_EMAIL_INTERVAL`: The interval (in seconds) of the one-time password (OTP) for email OTP. By default it is set to `600` (10 minutes).
- `ENVIRONMENT`: The environment of the API. By default it is set to `local`. It can be set to other strings. For production it should be set to `production`. Currently the only string having an impact are `local` and `production`.
- `FEATURE_FLAGS_FILE`: The name or path of the file that contains the feature flags relative to the `data` directory. By default it is set to `feature_flags.json`.
- `PROTECTED_INTERACTIVE_DOCS`: If the interactive docs (SwaggerUI) are protected (Ref. [Attribute Based Access Control](#attribute-based-access-control-abac)). By default it is set to `True`.
- **Database**
  - `DATABASE_URI`: the uri to the database to use if the next variables are not set. It **has to** be set if **ALL** of the next variables are not set.
  - `POSTGRES_SERVER`: The host of the database.
  - `POSTGRES_PORT`: The port of the database.
  - `POSTGRES_USER`: The user of the database.
  - `POSTGRES_PASSWORD`: The password of the database.
  - `POSTGRES_DB`: The name of the database.
- **EMAIL**
  - `CONTACT_EMAIL`: The contact email of your application.
  - `EMAIL_METHOD`: The method to use to send emails. By default it is set to `none`. It can be set to `none`, `smtp` or `mj`, `none` means no email will be sent and the error based on email verification will be ignored.
Either **all** of **SMTP** or **MailJet** variables must be set, else `EMAIL_METHOD` will be set to `none`.
  - **SMTP**
    - `SMTP_TLS`: If the SMTP server uses TLS.
    - `SMTP_PORT`: The port of the SMTP server.
    - `SMTP_HOST`: The host of the SMTP server.
    - `SMTP_USER`: The user of the SMTP server.
    - `SMTP_PASSWORD`: The password of the SMTP server.
    - `SMTP_SENDER_EMAIL`: The email of the sender (the email displayed in the email received by the client).
  - **MailJet**
    - `MJ_APIKEY_PUBLIC`: The public key of the MailJet API.
    - `MJ_APIKEY_PRIVATE`: The private key of the MailJet API.
    - `MJ_SENDER_EMAIL`: The email of the sender (the email displayed in the email received by the client).
- **Rate Limiter**
  - `RATE_LIMITER_ENABLED`: If the rate limiter is enabled. By default it is set to `False`.
  - `RATE_LIMITER_MAX_REQUESTS`: The maximum number of requests per window.
**WARNING**: Do not reduce this value too much (ref. [Rate Limiter](#rate-limiter)).
  - `RATE_LIMITER_WINDOW_SECONDS`: The time window in seconds.
  - **Redis**
    - `REDIS_URL`: *Optional*. The URL of the Redis server. If not set, the rate limiter will use an in-memory TTL cache (Time-To-Live cache).
- **3rd Party Login**
For the supported providers, refer to [Supported Providers](#supported-providers).
  - `API_CLIENT_ID_<PROVIDER>`: The client ID of the OAuth provider.
  - `API_CLIENT_SECRET_<PROVIDER>`: The client secret of the OAuth provider.

  For Bluesky, it is handled differently as it uses a different protocol (AtProto).

### Docker

### Local

#### Requirements

The project requires [Python](https://www.python.org) [3.13](https://www.python.org/downloads/release/python-3131) or higher.

## Usage

## Development

### Testing

#### Testing Requirements

In addition to the [Requirements](#requirements) for the deployment alone, the following packages are required:

#### Coverage

#### Linting

#### Load Testing

#### Documentation

### Useful Commands

```bash
pip install -r app/requirements.txt
pip install -r app/test/requirements.txt

# DEV (.root)
fastapi dev app/main.py --host=localhost --port=80
pylint app/ --rcfile=app/.pylintrc
pytest app/ --tb=no --md-report --md-report-verbose=1
coverage run -m pytest app/ --tb=no --md-report --md-report-verbose=1
coverage run -m pytest app/ | coverage html

# DEV (.root/app)
fastapi dev main.py --host=localhost --port=80
pylint .
pytest --tb=no --md-report --md-report-verbose=1
coverage run -m pytest --tb=no --md-report --md-report-verbose=1
coverage run -m pytest | coverage html

# DEV
alembic revision --autogenerate -m "<describe your changes>"

# PROD
fastapi run app/main.py --host=localhost --port=80
pylint app/ --fail-under=8 --output-format=parseable | tee app/reports/pylint-report.txt
pytest app/ --tb=no --md-report --md-report-output=app/reports/pytest.md
coverage run -m pytest app/ | coverage report
coverage report | tee reports/coverage.txt
```

## Credits

### Third-Party Libraries

This project uses open-source third-party libraries listed above. Each library is subject to its own license terms (MIT, Apache-2.0, BSD-3-Clause, etc.).
Refer to the respective library's documentation or repository for detailed license information.

The project is powered by [FastAPI](https://fastapi.tiangolo.com).
The database(s) are handled by [SQLAlchemy](https://docs.sqlalchemy.org/en/20/intro.html).
The authentication is handled by [Authlib](https://docs.authlib.org/en/latest) with [ATProto](https://atproto.blue/en/latest) for Bluesky integration.

Here's the list of the other libraries used in the project:

- [aiofiles](https://github.com/Tinche/aiofiles)
- [aiosqlite](https://aiosqlite.omnilib.dev/en/stable)
- [Alembic](https://alembic.sqlalchemy.org/en/latest)
- [APScheduler](https://github.com/agronholm/apscheduler)
- [bcrypt](https://github.com/pyca/bcrypt)
- [cachetools](https://github.com/tkem/cachetools)
- [itsdangerous](https://itsdangerous.palletsprojects.com/en/stable)
- [loguru](https://github.com/Delgan/loguru)
- [mailjet_rest](https://github.com/mailjet/mailjet-apiv3-python)
- [pillow](https://pillow.readthedocs.io/en/stable)
- [psycopg](https://www.psycopg.org)
- [pydantic](https://docs.pydantic.dev/latest)
- [pyotp](https://pyauth.github.io/pyotp)
- [qrcode](https://github.com/lincolnloop/python-qrcode)
- [redis](https://github.com/redis/redis-py)

## Note from the Creator

Thank your for reading everything. I am just a random developer. I don't do dev for a living it is just a hobby. There might still be some bugs, if you find any please let me know.

## License

Copyright 2024 LordLumineer

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Changelog
