# datasette-sierra-ils-auth

[![PyPI](https://img.shields.io/pypi/v/datasette-sierra-ils-auth.svg)](https://pypi.org/project/datasette-sierra-ils-auth/)
[![Changelog](https://img.shields.io/github/v/release/chimpy-me/datasette-sierra-ils-auth?include_prereleases&label=changelog)](https://github.com/chimpy-me/datasette-sierra-ils-auth/releases)
[![Tests](https://github.com/chimpy-me/datasette-sierra-ils-auth/actions/workflows/test.yml/badge.svg)](https://github.com/chimpy-me/datasette-sierra-ils-auth/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/chimpy-me/datasette-sierra-ils-auth/blob/main/LICENSE)

Datasette plugin for authenticating staff users against Sierra ILS REST API, with local role-based authorization.

## Features

- **Authentication** via Sierra ILS `/v6/users/validate` endpoint
- **Authorization** via local SQLite database with roles and permissions
- **Auto-provisioning** of new users on first successful Sierra login
- **Built-in admin account** for initial setup (optional)
- **Admin UI** for managing users and roles

## Installation

Install this plugin in the same environment as Datasette:

```bash
datasette install datasette-sierra-ils-auth
```

Or with pip:

```bash
pip install datasette-sierra-ils-auth
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SIERRA_API_BASE` | Yes | Sierra API base URL (e.g., `https://your-library.iii.com/iii/sierra-api/v6`) |
| `SIERRA_CLIENT_KEY` | Yes | Sierra API client key |
| `SIERRA_CLIENT_SECRET` | Yes | Sierra API client secret |
| `SIERRA_AUTH_ADMIN_PASSWORD` | No | Password for built-in `admin` account (bypasses Sierra) |
| `SIERRA_AUTH_DB_PATH` | No | Path to auth database (default: `./sierra_auth.db`) |
| `SIERRA_AUTH_COOKIE_NAME` | No | Session cookie name (default: `ds_sierra_auth`) |
| `SIERRA_AUTH_COOKIE_MAX_AGE` | No | Session duration in seconds (default: `86400` / 24 hours) |
| `SIERRA_AUTH_LOGIN_REDIRECT` | No | Redirect URL after login (default: `/`) |

### Sierra API Requirements

Your Sierra API key needs the **Users Write** role to validate user credentials. Create an API key in Sierra Administration (requires permission 1052).

## Usage

### Basic Setup

1. Set the required environment variables:

```bash
export SIERRA_API_BASE=https://your-library.iii.com/iii/sierra-api/v6
export SIERRA_CLIENT_KEY=your-api-key
export SIERRA_CLIENT_SECRET=your-api-secret
```

2. Run Datasette:

```bash
datasette your-database.db
```

3. Users can log in at `/-/sierra-auth/login` using their Sierra staff credentials.

### Built-in Admin Account

For initial setup or when Sierra API is unavailable, you can enable a local admin account:

```bash
export SIERRA_AUTH_ADMIN_PASSWORD=your-secure-password
```

This creates an `admin` user that:
- Bypasses Sierra API authentication (uses local password)
- Has the `admin` role with full permissions
- Password is updated on each startup if changed

### Admin UI

Users with the `admin` role or `manage-users` permission can access:

- `/-/sierra-auth/admin/users` - List all users
- `/-/sierra-auth/admin/users/<id>` - Edit user roles and status

## Database

The plugin creates a `sierra_auth.db` SQLite database to store:

- **users** - User accounts (auto-created on first Sierra login)
- **roles** - Available roles (viewer, staff, admin by default)
- **user_roles** - Role assignments
- **permissions** - Permission definitions
- **role_permissions** - Permission assignments to roles
- **auth_log** - Audit log of authentication events

### Default Roles

| Role | Description | Default Permissions |
|------|-------------|---------------------|
| `viewer` | Default for new users | `view-instance`, `view-database-collection` |
| `staff` | Library staff | Above + `view-database-patrons` |
| `admin` | Full access | All permissions |

### Persisting the Database (Docker/Podman)

The auth database stores user roles, permissions, and audit logs. To persist this data across container restarts, mount a volume:

```yaml
# docker-compose.yml
services:
  datasette:
    image: your-datasette-image
    environment:
      - SIERRA_API_BASE=${SIERRA_API_BASE}
      - SIERRA_CLIENT_KEY=${SIERRA_CLIENT_KEY}
      - SIERRA_CLIENT_SECRET=${SIERRA_CLIENT_SECRET}
      - SIERRA_AUTH_ADMIN_PASSWORD=${SIERRA_AUTH_ADMIN_PASSWORD}
      - SIERRA_AUTH_DB_PATH=/data/sierra_auth.db
    volumes:
      - auth_data:/data

volumes:
  auth_data:
```

Or with Docker/Podman run:

```bash
docker run -v auth_data:/data \
  -e SIERRA_AUTH_DB_PATH=/data/sierra_auth.db \
  -e SIERRA_API_BASE=... \
  your-datasette-image
```

## How It Works

1. User submits Sierra login + password at `/-/sierra-auth/login`
2. Plugin validates credentials against Sierra `/v6/users/validate`
3. On success (HTTP 204): user is looked up or created in local database
4. User's roles and permissions are loaded from local database
5. Signed session cookie is set
6. On subsequent requests, `actor_from_request` hook rebuilds actor from cookie

## Development

To set up this plugin locally:

```bash
git clone https://github.com/chimpy-me/datasette-sierra-ils-auth
cd datasette-sierra-ils-auth
uv sync
```

Run tests:

```bash
uv run pytest
```

Run Datasette with the plugin:

```bash
uv run datasette
```

## License

MIT License
