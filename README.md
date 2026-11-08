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
- **roles** - Available roles (only `admin` by default; others come from `seed_roles`)
- **user_roles** - Role assignments
- **permissions** - Permission definitions
- **role_permissions** - Permission assignments to roles
- **auth_log** - Audit log of authentication events

### Roles

A fresh (schema v2) database has exactly one role, `admin`, which holds every
permission. **There is no default role**: a user created on first sign-in has no
role and no permissions until an administrator grants one. Such a user who reaches
a protected page sees "You are signed in as `<login>` but have no role yet; ask
the administrator." (status 403).

Define other roles in Datasette metadata under the plugin's key:

```yaml
plugins:
  datasette-sierra-ils-auth:
    default_role: null          # optional; name of a role new users receive (default: none)
    trust_forwarded: false      # optional; true behind exactly one reverse proxy (see Sign-in attempt cap)
    seed_roles:                 # optional; applied at startup
      reviewer:
        - alt-review-edit
      viewer:
        - view-database-collection
```

- `seed_roles` creates each role and any missing permission rows, idempotently. It
  never removes a grant an administrator made through the admin UI.
- `default_role` names a role to give every newly created user. Leave it unset
  (null) to give new users nothing.
- Upgrading a v1 database keeps its roles, users and grants as they are; only
  `roles.is_default` is cleared. v0.1.0's `viewer` and `staff` seeds are not
  created on new databases.

### Sign-in attempt cap

After 5 failed sign-ins within 15 minutes, further attempts for that username
(case-insensitive) or from that address get a 429 ("Too many failed sign-in
attempts; try again in 15 minutes") and are checked against nothing: no local
password check and no Sierra call. Failures are missing credentials, a wrong
password, a non-204 Sierra response and a disabled account. A successful sign-in
neither counts nor resets the count. The counter is in memory, one per Datasette
process, and starts empty on restart. Blocked attempts are logged as
`login_throttled` (username and address, never the password).

The address is the socket peer by default. Set `trust_forwarded: true` only when
Datasette sits behind exactly one reverse proxy that appends the client address
(`tailscale serve`, Caddy): the address is then the last `X-Forwarded-For` entry,
since earlier entries are whatever the client sent. Without a proxy, leave it off.

On any Sierra `users/validate` response other than 204, `auth_log.details` records
`sierra_status=<status>` and, when the body has one, `code=<n>` (Sierra answers bad
credentials with 400, code 108). The body text and the password are never logged.

**Do not put `view-instance` on any role except `admin`.** This plugin's
`permission_allowed` runs after Datasette's built-in default and the last non-None
result wins, so a role holding `view-instance` returns `True` and overrides an
instance-level `allow: false`: every signed-in holder could then see the whole
instance, even one that is locked down.

### Redirects and links honour `base_url`

Every redirect and link the plugin emits goes through `datasette.urls.path()`, so
it works when Datasette is served under a prefix (`--setting base_url /alt-review/`).
`SIERRA_AUTH_LOGIN_REDIRECT` is a path relative to `base_url`.

## Changelog

### 0.3.1

- Release-only: the PyPI publish workflow can check out the repo (job permissions gain
  `contents: read`). The code is the same as 0.3.0, which was never published to PyPI.

### 0.3.0

- The session cookie is set with `Secure`.
- Local passwords (the built-in admin) are hashed with scrypt (n=16384, r=8, p=1) and
  compared in constant time. 0.2.0 `salt$sha256` hashes still verify; the admin row is
  rehashed at the next startup.

### 0.2.0

- **Breaking:** no default role. `viewer` and `staff` are no longer seeded; new
  users have no role until granted one. Schema version is now 2 (v1 databases
  migrate in place; existing roles and grants are kept, `is_default` is cleared).
- New plugin config `seed_roles` and `default_role` (see Roles).
- A signed-in user with no role who is denied a page sees a "no role yet" 403 page
  (a `forbidden` hook, plus the plugin's own admin pages).
- Failed sign-in cap: 5 per 15 minutes per username and per address, 429 beyond
  it; new plugin config `trust_forwarded` (default false) for the address behind a
  proxy.
- Non-204 `users/validate` responses are logged as `sierra_status=<status>` (and
  `code=<n>`) in `auth_log.details`.
- All redirects and links (login, logout, admin bounce, menu, templates) respect
  Datasette's `base_url`; `SIERRA_AUTH_LOGIN_REDIRECT` is relative to it.

### 0.1.0

- Initial release.

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
