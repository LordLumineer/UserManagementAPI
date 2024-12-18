# ![UserManagementLogo](/assets/favicon.png) UserManagementAPI

<!-- Badges -->
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Lint and Test](https://github.com/LordLumineer/UserManagementAPI/actions/workflows/Commit_lint_test.yml/badge.svg?branch=master)](https://github.com/LordLumineer/UserManagementAPI/actions/workflows/Commit_lint_test.yml)

[![Pytest](https://raw.githubusercontent.com/LordLumineer/UserManagementAPI/45b5f23657961c3d0fc2db18df0f0924feb0b665/img/coverage_badge.svg)](https://raw.githubusercontent.com/LordLumineer/UserManagementAPI/refs/heads/main/reports/pytest.md)
[![Pylint Score](https://raw.githubusercontent.com/LordLumineer/UserManagementAPI/45b5f23657961c3d0fc2db18df0f0924feb0b665/img/pylint_badge.svg)](https://raw.githubusercontent.com/LordLumineer/UserManagementAPI/refs/heads/main/reports/pylint.txt)
[![Coverage](https://raw.githubusercontent.com/LordLumineer/UserManagementAPI/45b5f23657961c3d0fc2db18df0f0924feb0b665/img/coverage_badge.svg)](https://raw.githubusercontent.com/LordLumineer/UserManagementAPI/refs/heads/main/reports/coverage.txt)

## Introduction

UserManagementAPI is a web application that allows you to manage users.
It's main goal is as a cleaner user management base (compared to my older projects) to be integrated into my future projects.

With the scopes keeping on increasing, the API in itself could be a used as a service in itself.

## Features

UserManagementAPI leverage the [FastAPI](https://fastapi.tiangolo.com) capabilities (thanks to [Starlette](https://www.starlette.io/)) as an ASGI web framework that supports asynchronous code, and therefore can use asynchronous database access and file I/O.

### Local Users

As the name of the project suggest, it is a local user management system.

- **UUID**s are unique generated when the user is created.
- **Username**s are unique and have to be provided when creating a new user and smaller than 32 characters, with only lowercase letters, numbers, and underscores.
- **Display name**s are optional, if not provided, the username will be used. Display names have to be the same as the username except for underscores that can be replaced with spaces and characters can be capitalized.
- **Email**s are unique and have to be provided when creating a new user. If the `email_method` is not set to `none`, then the email has to be valid (i.e. accept deliverability) and an email verification email will be sent.
Emails are also used to automatically connect [3rd party accounts](#3rd-party-login) to the local account unless specified otherwise.
- If the email is verified the flag **`email_verified`** will be set to `True` by default it is set to `False`.
- The password is hashed bcrypt before being stored in the database [code](/app/core/security.py#L100). The plain text password is **NEVER** stored nor is it logged, only the **hashed password** is stored.
- **OTP method** represents the method the user chose to use for OTP verification. OTP methods are `authenticator`, `email`, and `none`. For authenticator app (such as Google Authenticator, Authy, and Microsoft Authenticator, etc.) it has to be set to `authenticator`, `email` is the value if you prefer to use an email (the OTP codes will be sent via email and have a longer validity window), and `none` the user isn't using 2FA.
- **OTP secret** is a random string of 32 letters based on the user's uuid as seed. This is the secret used to generate the OTP codes, it is unique for each user and is generated when the user is created.
- **User roles** are an array of strings that represent the roles the user has. The roles are defined in the [`app.core.permissions`](/app/core/permissions.py#L40) module, the roles are `admin`, `moderator`, `tester`, and `user`. Currently the role `tester` is not used anywhere in the API but it is included for future use.
- **Description** is an optional field that can be used to store any additional information about the user. It is limited to 256 characters.
- **Created at** and **updated at** are timestamps that are automatically set when the user is created and updated.
- If the user has only been created by an external source and hasn't updated their password (for the password of the local account to be set), the flag **`is_external_only`** will be set to `True` by default it is set to `False`.
- If the user **is active** the flag `is_active` will be set to `True` by default it is set to `True`. Reasons for the user to be inactive are:
  - The user is banned
  - The user is being deleted (in case the deletion fails, the user is set to inactive as a safety measure)
  - The user forgot their password and requested a password reset (if the password is successfully reset, the user is set to active). For password change (when the user is logged in) the user stay active.
- **User History** is and array of JSON objects that represent the history of the user actions.
- **Blocked UUIDs** is an array of UUIDs that represent the users that the user has blocked. Blocked users can't see the user information (ref. to [Attribute Based Access Control](#attribute-based-access-control-abac)).
- **Profile picture** is the File object associated with the **`profile_picture_id`**. When the user is created the `profile_picture_id` is set to `null` and the displayed profile picture is generated on request based on the user's display name (i.e. for a display name `John Doe` the profile picture will be an gray square with the initials `JD`).
A profile picture is limited to 512x512 pixels and it has to be a valid image (the file extension must be one of `png`, `jpg`, `jpeg`, `gif`, or `bmp`).
For more information refer to the [file uploads](#file-uploads) section.
- **External Accounts** is an array of ExternalAccount objects that represent the external accounts (used with OAuth (ref. [3rd Party Login](#3rd-party-login))) linked to the user.
- **OAuth Tokens** is an array of OAuthToken objects that represent the OAuth tokens (used by Authlib for [3rd Party Accounts](#3rd-party-login)) linked to the user.
- **Files** is an array of File objects that represent the files the user has uploaded, this is a many to many relationship as for more complex projects you may want the user to upload that is linked to another kind of object (like a post) This is used here if the admins have interact with a file for another user, the file will be linked to both the user **and** the admin.
For more information refer to the [file uploads](#file-uploads) section.

Here is the User model stored in the database:

```json
{
  "uuid": "string(36 | uuid v4) | Unique | primary key",
  "username": "string | Unique",
  "display_name": "string",
  "email": "string | Unique",
  "email_verified": "boolean",
  "hashed_password": "string",
  "otp_method": "string",
  "otp_secret": "string | Nullable",
  "roles": "string[]",
  "description": "string | Nullable",
  "created_at": "integer",
  "updated_at": "integer",
  "is_external_only": "boolean",
  "is_active": "boolean",
  "user_history": "JSON[]",
  "blocked_uuids": "string[]",
  "profile_picture_id": "string | Nullable",
  "profile_picture": "File | Nullable | One-to-one relationship",
  "external_accounts": "ExternalAccount[] | One-to-many relationship",
  "oauth_tokens": "OAuthToken[] | One-to-many relationship",
  "files": "File[] | Many-to-many relationship"
}
```

### Rate Limiter

A simple rate limiter is implemented using either [redis](https://redis.io) or a [TTL cache](https://cachetools.readthedocs.io/en/latest/#cachetools.TTLCache).

It has two parameters:

- `max_requests`: The maximum number of requests allowed within the window.
- `window_seconds`: The window size in seconds.

If more than the `max_requests` are made within the `window_seconds`, the requests return a [429 response](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429).

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

### Attribute Based Access Control (ABAC)

Endpoints can be protected with attribute based access control (ABAC).
Unlike [Feature Flags](#feature-flags), ABAC are **NOT** handled by a middleware or decorator but is instead handled inside of the endpoints and requires the user to be authenticated. More precisely it takes a `User` object as parameter as well as the `resource` being accessed and the type of the `action` the user will do on the `resource` (i.e. `read`, `write`, `delete`, etc).

You want to use ABAC for more precise access control as they can use `lambda` functions to implement more complex logic.

The permissions are defined in the [`app.core.permissions`](/app/core/permissions.py#L50) module.

They look as follows:

```python
ROLES: RolesWithPermissions = {
    "admin": {
        "<RESOURCE_1>": {
            "create": True,
            "read": True,
            "update": True,
            "delete": True
        },
        "<RESOURCE_2>": {
            "create": True,
            "read": True,
        },
        "<RESOURCE_3>": {
            "read": False,
            "update": True,
            "delete": lambda user, other_user: user.uuid == other_user.uuid
        },
    },
    "<OTHER_ROLE>": {
        "RESOURCE_1": {
            "create": lambda user, new_user: not list(set(["admin", "moderator"]) & set(new_user.roles)),
            "read": True,
            "delete": False
        },
        "RESOURCE_3": {
            "read": lambda user, other_user: not list(set(["admin", "moderator"]) & set(other_user.roles)),
            "update": False,
            "delete": False
        }
    },
}
```

If the resource or action doesn't exist, the request will be denied.

### Feature Flags

In order to enable/disable specific features, a feature flag can be used to toggle a feature on or off.
For more complex access if the endpoint requires to be authenticated (i.e. requires the use of the `Authorization` header with a Bearer token), a feature flag can be used for A/B testing, role based access, and combination of the above.
For percentage based access it bases itself on a hash of the user UUID to keep the experience consistent.

On startup, each endpoints get an feature flag name base on the name of the function of the endpoint. If the name isn't already set in the feature flag file, it will be set to `true` (feature enabled).

Unlike [Attribute Based Access Control](#attribute-based-access-control-abac), feature flags can be updated at runtime by administrators with the `PATCH /admin/feature-flags` endpoint. It takes in the form two parameters: `remove` and `add`, where `add` and `remove` are list of feature flags to add and remove respectively. Additionally it is handled by the `FeatureFlagMiddleware` (before the execution of the endpoint (outside of the endpoint function)).

Here a simple example of a feature flag file:

```json
{
    "FEATURE_FLAG_1": true,
    "FEATURE_FLAG_2": false,
    "DANGEROUS_AB_TEST_FEATURE": [
      { "percentageOfUsers": 0.25 }
    ],
    "AB_TEST_FEATURE": [
      { "percentageOfUsers": 0.25 },
      { "userRoles": ["admin"] }
    ],
    "ROLE_BASED_FEATURE": [
      { "userRoles": ["tester", "admin"] }
    ],
    "MULTIPLE_ACCESS_FEATURE": [
      { "percentageOfUsers": 0.30, "userRoles": ["user"] },
      { "userRoles": ["admin", "tester"] }
    ]
}
```

Here `DANGEROUS_AB_TEST_FEATURE` makes that everyone **including admins** have a 25% chance to get the feature enabled, it is recommended for A/B testing to include a role based access for admins like `AB_TEST_FEATURE`.
In the `AB_TEST_FEATURE`, all users have a 25% chance to get the feature enabled, unless they have the role `admin` in which case they will always get the feature enabled.
For `ROLE_BASED_FEATURE`, the user must have the role `tester` or `admin` to get the feature enabled.
Finally, the `MULTIPLE_ACCESS_FEATURE` makes that 30% of the users with the role `user` have the feature enabled, unless they have the role `admin` or `tester`. So if a user has **ONLY** the role `moderator`, they will **NOT** have the feature enabled.

Custom feature flags can be added to the endpoints by using a decorator `feature_flag`. If the feature flag is not set in the feature flag file, the feature is enabled until the feature flag is set in the feature flag file.

```python
from app.core.permissions import feature_flag

@feature_flag("DISABLE_FEATURE")
@app.get("/ping", tags=["DEBUG"])
def _ping():
    return "pong"
```

In that case the feature flag file might look like this:

```json
{
    "_PING": true,
    "DISABLE_FEATURE": false
}
```

### Database

The currently supported databases are:

- [SQLite](https://www.sqlite.org)
- [PostgreSQL](https://www.postgresql.org)

Some other databases might be supported in the future such as:

- [MySQL](https://www.mysql.com)
- [MariaDB](https://mariadb.org)
- [MongoDB](https://www.mongodb.com)

### File Uploads

User can upload a file to the server using the `POST /user/{uuid}/file` or `POST /file` endpoints while being authenticated. The file will be linked to the user who is making the request.

The file is stored in the `users/{uuid}` directory in the `data` directory.

- The **filename** is the filename of the file uploaded, it has to be unique. For profile picture the file is renamed to `pfp_{uuid}.{file_extension}`.
- The **file type** is the mime type of the file uploaded (i.e. the extension of the file (`png`, `pdf`, `docx`, etc.)).
- The **file path** is the internal path of the file the server uses to then serve the file, it is not available to the user.
- The **description** is an optional field to give more information about the file.
- The **created at** is the timestamp when the file was created.
- The **created by** is the User object of the user who created the file associated with the `created_by_uuid` field.
- the **file url** is a computed field that is given to the user to get the file itself (and to the file data).

In the database the file is stored as:

```json
{
  "id": "integer | primary key | auto increment",
  "file_name": "string | unique",
  "file_type": "string",
  "file_path": "string",
  "description": "string | nullable",
  "created_at": "integer",
  "created_by_uuid": "string",
  "created_by": "User | One-to-one relationship"
}
```

### 3rd Party login

User API uses the `email` linked to the third party account to create / link with a local account.

You can login with a 3rd party account using the `/oauth/{3rd-party-provider}` endpoint.

- If the 3rd party account is already linked with a local account, you will get the login response (the same as the `/login` endpoint with `username or email` and `password`).
- If the 3rd party account is not linked with a local account, and find a local account with the same email and the email has been verified for the local account (and 3rd party account), it will link the 3rd party account with the local account and complete the login.
- If the emails (local **and** 3rd party) aren't verified, it will raise an error (unless the `email_method` is set to `none` only the 3rd party email has to be verified).
- If the 3rd party account is not linked with a local account, it will create a new local account and link it with the 3rd party account and complete the login.

If you have a 3rd party account that you want to link with a local account but the email doesn't match with the email registered with the local account, you can use the `/oauth/{3rd-party-provider}/link` endpoint while being logged in with the local account (Header: `Authorization: Bearer {token}`).

- If the 3rd party account is not already linked with a local account, it will link it with the local account.
- If the 3rd party account is already linked with a local account that isn't yours, you will receive an error (based on `local_account.uuid`).
- If the 3rd party account is already linked with a local account that is yours, you will also receive an error (based on `3rd_party_account.id`).

If the local account doesn't have a profile picture, the picture from the 3rd party account will be used.

For more information you can read the [associated code](./app/api/routes/oauth.py#L34-L275).

#### Supported Providers

Refer to each provider's documentation for more information, the API client ID and client secret are required.

- Bluesky / AtProto *(NOT SUPPORTED YET)*
- Discord
- GitHub
- Google
- Reddit *(NOT SUPPORTED YET)*
- Twitch
- Twitter / X *(NOT SUPPORTED YET)*

***WARNING:*** *Twitter integration is limited, you can link a twitter account to a local one with no issues then login with it, however first time login will fail.*
*furthermore it is limited by the Twitter API own limitations*

The External accounts are represented with multiple information:

- **Provider**s are the names of the providers used.
- **External account ID**s is the id of the account on the provider.
- **Username**s are the username of the account on the provider.
- **Display name**s are the display name of the account on the provider.
- **Email**s are the email of the account on the provider. If the provider has multiple emails (like Github), the first email with witch it successfully linked will be used.
- **Profile picture URL**s are the url of the profile picture of the account on the provider.
- **User UUID**s are the UUIDs of the local account linked with the 3rd party account.

To simplify refreshing the token, [Authlib](https://docs.authlib.org/en/latest) recommends to store them in the database, here's what is stored:

- **OAuth Version** the version of the OAuth protocol used (1 or 2).
- The **Provider**
- For OAuth 1:
  - **OAuth Token** the token of the account on the provider.
  - **OAuth Token Secret** the token secret of the account on the provider.
- For OAuth 2:
  - **Token Type** the token type of the account on the provider (Bearer).
  - **Access Token** the access token of the account on the provider.
  - **Refresh Token** the refresh token of the account on the provider.
  - **Expires At** the expiration date of the access token of the account on the provider.
- **User UUID** the UUID of the local account linked with the 3rd party account.

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
  - `DATABASE_URI`: The uri to the database to use if the next variables are not set.
  It is not recommended to define the url directly, and instead use the next variables.
  It **has to** be set if **ALL** of the next variables are not set.
  If it is not set the application will use a SQLite database in the `data` directory.
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

Docker is the recommended way to deploy the application. You will find bellow two examples of docker-compose configuration files.

#### Simplest Example

The simplest docker-compose configuration file is as follows:

```yaml
version: '3'
services:
  app:
    image: lordlumineer/user-manager:latest
    ports:
      - "8000:8000"
    environment:
      # - ENVIRONMENT=production # Optional
      - JWT_SECRET_KEY=<YOUR_SECRET_KEY>
```

With such configuration, some functionalities are disabled.

- Log files are disabled.
- The emails are disabled (therefore the error based on email verification will be ignored).
- No 3rd party login.
- The rate limiter is disabled.
- The feature flags are disabled.
- The database is handled with a SQLite database in the `data` directory.

#### Complete Example

The complete and more complex docker-compose configuration file is as follows:

```yaml
version: '3'

services:
  app:
    container_name: user-manager-api
    restart: unless-stopped
    image: lordlumineer/user-manager:latest
    ports:
      - "8000:8000"
    environment:
      - BASE_URL=https://UserManager.<DOMAIN>
      - FRONTEND_URL=https://YOUR_FRONTEND.<DOMAIN>
      - API_STR=/userAPI
      - ENVIRONMENT=production

      - LOG_LEVEL=INFO
      - LOG_FILE_ENABLED=True
      - LOG_FILE_LEVEL=WARNING
      - LOG_FILE_ROTATION='100 MB'
      - LOG_FILE_RETENTION='24h'

      - JWT_SECRET_KEY=<YOUR_SECRET_KEY>
      - JWT_EXP=60 # in minutes

      - OTP_LENGTH=8
      - OTP_AUTHENTICATOR_INTERVAL=30 # in seconds
      - OTP_EMAIL_INTERVAL=900 # in seconds

      - FEATURE_FLAGS_ENABLED=True
      - FEATURE_FLAGS_FILE=feature_flags.json

      - PROTECTED_INTERACTIVE_DOCS=True # Optional

      - POSTGRES_SERVER=db
      - POSTGRES_PORT=5432
      - POSTGRES_USER=<YOUR_USER>
      - POSTGRES_PASSWORD=<YOUR_PASSWORD>
      - POSTGRES_DB=UserManagerAPI

      - RATE_LIMITER_ENABLED=True
      - RATE_LIMITER_MAX_REQUESTS=300
      - RATE_LIMITER_WINDOW_SECONDS=900
      - REDIS_URL=redis://redis:6379/0 # NOT YET TESTED

      - CONTACT_EMAIL=<YOUR_EMAIL> # e.g. "support@<YOUR_DOMAIN>"
      - EMAIL_METHOD=smtp # smtp, mj, none

      # MailJet (Not required if EMAIL_METHOD=smtp or EMAIL_METHOD=none)
      # - MJ_APIKEY_PUBLIC=<YOUR_MAILJET_PUBLIC_APIKEY>
      # - MJ_APIKEY_PRIVATE=<YOUR_MAILJET_PRIVATE_APIKEY>
      # - MJ_SENDER_EMAIL=<YOUR_MAILJET_EMAIL> # e.g. "no-reply@<YOUR_DOMAIN>"

      # SMTP (Not required if EMAIL_METHOD=mj or EMAIL_METHOD=none)
      - SMTP_TLS=True
      - SMTP_PORT=587
      - SMTP_HOST=smtp.<YOUR_DOMAIN>
      - SMTP_USER=<YOUR_SMTP_USER>
      - SMTP_PASSWORD=<YOUR_SMTP_PASSWORD>
      - SMTP_SENDER_EMAIL=<YOUR_SMTP_EMAIL> # e.g. "no-reply@<YOUR_DOMAIN>"

      - API_CLIENT_ID_GITHUB=<YOUR_GITHUB_API_CLIENT_ID>
      - API_CLIENT_SECRET_GITHUB=<YOUR_GITHUB_API_CLIENT_SECRET>
      # OTHER PROVIDERS (Google, Discord, etc.)

    volumes:
      - <YOUR_LOCAL_FOLDER>/userAPI/data:/data  # Map local folder for persistent storage
    depends_on:
      db:
        condition: service_healthy

  db:
    container_name: user-manager-database
    restart: unless-stopped
    image: postgres
    # set shared memory limit when using docker-compose
    shm_size: 128mb
    ports:
      - "5432:5432"
    volumes:
      - <YOUR_LOCAL_FOLDER>/userAPI/database:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: UserManagerAPI
      POSTGRES_USER: <YOUR_USER>
      POSTGRES_PASSWORD: <YOUR_PASSWORD>
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U <YOUR_USER> -d UserManagerAPI"]
      interval: 5s
      timeout: 5s
      retries: 30

  adminer:
    container_name: user-manager-adminer
    image: adminer
    restart: unless-stopped
    ports:
      - "8001:8080"
    depends_on:
      db:
        condition: service_healthy
```

### Local

If you prefer to run the application locally, and not use docker, it will require more configuration.

#### Requirements

The project requires [Python](https://www.python.org) [3.13](https://www.python.org/downloads/release/python-3131) or higher.

To install the [required packages](#third-party-libraries), run the following command in the root directory:

```bash
pip install -r app/requirements.txt
```

#### Configuration

1. Clone the repository:

    ```bash
    git clone https://github.com/LordLumineer/UserManager.git
    cd UserManager
    ```

2. Create and populate the `.env` file:

    ```bash
    cp app/.env.example app/.env
    ```

    Refer to the [Environment Variables](#environment-variables) section for more information about which environment variables to set and their default values.

3. Use virtual environment:

    ```bash
    python3 -m venv .venv
    source venv/bin/activate
    ```

4. Install the requirements:

    ```bash
    pip install -r app/requirements.txt
    ```

5. Run the application:

    ```bash
    fastapi run app/main.py --host=0.0.0.0 --port=8000
    ```

    You can modify the port and host as you want. Be careful with the base url defined in the `.env` file.

## Usage

## Development

For development I would recommend using the auto generated SQLite database (and not run a full database), this helps for resets as it is a single file.

### Docker in Development

Here is an example of a docker-compose configuration file for development:

```yaml
services:
  app:
    restart: unless-stopped
    build:
      context: .
      dockerfile: Dockerfile_dev
    ports:
      - "80:8000"
    environment:
      - ENVIRONMENT=local
      - LOG_LEVEL=DEBUG
      - LOG_FILE_ENABLED=False
      - JWT_EXP=180 # in minutes
    volumes:
      - <YOUR_LOCAL_FOLDER>/userAPI/data:/data
    watch:
      # NOT YET TESTED
```

### Local in Development

If you prefer to manually run the application locally, and not use docker, the approach is really similar to the one to [deploy the application locally](#local). The main differance is in the run command:

```bash
fastapi dev app/main.py --host=localhost --port=80
```

This lets you access the application at `http://localhost`

### Database version

As database changes could be made in the future, from V[1.0.0](insert-link) of the project, at each release, the database the database version will be updated.
Database migration is handled by [Alembic](https://alembic.sqlalchemy.org/en/latest).

The command to generate the new version needs to be run manually from either the root folder of the project or the `app` folder.

```bash
alembic revision --autogenerate -m "V<VERSION>-<MAIN_CHANGES>"
```

No commands need to be run to upgrade the database, the application will automatically upgrade the database to the latest version.

### Testing

To ensure good practices the project implement various tests to ensure that the code is properly tested.

#### Testing Requirements

In addition to the [Requirements](#requirements) for the deployment alone, the following packages are required:

- **[anybadge](https://github.com/jongracecox/anybadge)**: Generate badges for the README
- **[coverage](https://coverage.readthedocs.io/en/latest/index.html)**: Test Code Coverage
- **[pylint](https://pylint.readthedocs.io/en/latest)**: Test Code Quality
- **[pytest](https://docs.pytest.org/en/stable)**: Unit Testing
- **[pytest-asyncio](https://pytest-asyncio.readthedocs.io/en/latest)**: Enabling async code testing
- **[pytest-md-report](https://github.com/thombashi/pytest-md-report)**: Generating Markdown reports for Pytest
- **[pytesseract](https://github.com/madmaze/pytesseract)**: Enabling OCR testing (for the generation of profile pictures and other images (QR codes, etc.))

In the root directory:

```bash
pip install -r app/test/requirements.txt
```

#### Unit Testing

To enforce proper functionality of the code, the project needs to pass **ALL** of the [unit tests](https://docs.pytest.org/en/stable), this is coupled with [code coverage](#coverage) to ensure new code is also tested.

Before any commit or pull request, it is recommended to manually check (and avoid the action to be failed), to do so:

  ```bash
  pytest app/ --tb=no --md-report --md-report-verbose=1
  ```

  The `--tb=no`, `--md-report` and `--md-report-verbose=1` are optional parameters and helps you to get a more readable report.

In order to generate manually a report in the root folder of the project run:

```bash
pytest app/ --tb=no --md-report --md-report-output=reports/pytest.md
```

#### Coverage

New code needs to be tested, to ensure that it is requires the code [coverage](https://coverage.readthedocs.io/en/latest/index.html) to be at least <FIXME>%.

Before any commit or pull request, it is recommended to manually check (and avoid the action to be failed), to do so:

  ```bash
  coverage run -m pytest app/ | coverage html
  ```

The `coverage html` can help you to get a more visual report to check exactly what is missing.

In order to generate manually a report in the root folder of the project run:

```bash
coverage run -m pytest app/ | coverage report | tee reports/coverage.txt
```

#### Linting

To ensure proper code quality, the project checks the code with [Pylint](https://pylint.readthedocs.io/en/latest).
In order for the code to be successful, a code quality of <FIXME>/10 or higher is required.

To run pylint manually (before committing code or doing a PR):

- If you are in the root folder of the project:

    ```bash
    pylint app/ --rcfile=app/.pylintrc
    ```

- If you are in the `app` folder of the project:

    ```bash
    pylint .
    ```

In order to generate manually a report in the root folder of the project run:

```bash
pylint app/ --rcfile=app/.pylintrc --fail-under=<FIXME> --output-format=parseable | tee reports/pylint.txt
```

#### Load Testing

For load testing [k6](https://k6.io) is used, for more information please refer to [k6 documentation](https://grafana.com/docs/k6/latest) qnd the [k6 test file](/load-test/load-test.js).

The goal is to have an average of at least FIXME requests per second and an average response time of FIXME ms.

To run the load test:

1. Have k6 installed

    You can find the instructions here: [https://grafana.com/docs/k6/latest/set-up/install-k6](https://grafana.com/docs/k6/latest/set-up/install-k6)

2. Run the load test:

    ```bash
    k6 run load-test/load-test.js
    ```

    The results should look something like this:

    ```bash
     execution: local
        script: .\load-test\load-test.js
        output: -

     scenarios: (100.00%) 1 scenario, 1 max VUs, 1m30s max duration (incl. graceful stop):
              * default: Up to 1 looping VUs for 1m0s over 1 stages (gracefulRampDown: 30s, gracefulStop: 30s)


     data_received..................: 1.1 MB 17 kB/s
     data_sent......................: 1.1 MB 17 kB/s
     http_req_blocked...............: avg=80.03µs  min=0s     med=0s       max=8.81ms   p(90)=0s       p(95)=0s
     http_req_connecting............: avg=4.51µs   min=0s     med=0s       max=528.29µs p(90)=0s       p(95)=0s
     http_req_duration..............: avg=442.07ms min=5.16ms med=44.63ms  max=1.94s    p(90)=1.46s    p(95)=1.59s
       { expected_response:true }...: avg=494.21ms min=5.16ms med=243.77ms max=1.94s    p(90)=1.51s    p(95)=1.6s
     http_req_failed................: 11.11% 13 out of 117
     http_req_receiving.............: avg=1.67ms   min=0s     med=591.7µs  max=13.93ms  p(90)=8.41ms   p(95)=10.63ms
     http_req_sending...............: avg=80.87µs  min=0s     med=0s       max=1.5ms    p(90)=509.41µs p(95)=544.08µs
     http_req_tls_handshaking.......: avg=0s       min=0s     med=0s       max=0s       p(90)=0s       p(95)=0s
     http_req_waiting...............: avg=440.31ms min=5.16ms med=43.99ms  max=1.94s    p(90)=1.46s    p(95)=1.59s
     http_reqs......................: 117    1.8064/s
     iteration_duration.............: avg=4.98s    min=4.32s  med=5.01s    max=5.68s    p(90)=5.48s    p(95)=5.58s
     iterations.....................: 13     0.200711/s
     vus............................: 1      min=1         max=1
     vus_max........................: 1      min=1         max=1


     running (1m04.8s), 0/1 VUs, 13 complete and 0 interrupted iterations
     default ✓ [======================================] 0/1 VUs  1m0s
    ```

### Documentation

If new endpoints are created please make sure to properly write their docstring following [numpydoc style](https://numpydoc.readthedocs.io/en/latest/example.html#example) as much as possible.

Another important place to properly write information is in the decorators of the endpoints.

### Useful Commands

These are a bunch of commands that have been used before grouped in a single place.

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

This project is released under the [Apache-2.0](LICENSE).

## Changelog

TODO
