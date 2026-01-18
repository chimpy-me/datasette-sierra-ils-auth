# datasette-sierra-ils-auth Plugin Specification

A Datasette plugin for authenticating staff users against Sierra ILS REST API, with local authorization management.

## Overview

This plugin provides:

- **Authentication** via Sierra ILS `/v6/users/validate` endpoint (staff login + password)
- **Authorization** via local SQLite database (`sierra_auth.db`) for roles and permissions
- **Auto-provisioning** of new users on first successful Sierra login (with minimal default privileges)

## Architecture

```text
┌────────────────────────────────────────────────────────────────┐
│                         Datasette                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           datasette-sierra-ils-auth plugin               │  │
│  │  ────────────────────────────────────────────────────────│  │
│  │  1. User submits Sierra login + password                 │  │
│  │  2. Validate against Sierra /v6/users/validate           │  │
│  │  3. On 204: lookup/create user in sierra_auth.db         │  │
│  │  4. Build actor from local roles + permissions           │  │
│  │  5. Set signed session cookie                            │  │
│  └─────────┬───────────────────────────┬────────────────────┘  │
│            │                           │                       │
│  ┌─────────▼─────────┐      ┌──────────▼──────────┐            │
│  │  Sierra REST API  │      │  sierra_auth.db     │            │
│  │  (authentication) │      │  (authorization)    │            │
│  │                   │      │  • users            │            │
│  │  "Is this person  │      │  • roles            │            │
│  │   who they say?"  │      │  • user_roles       │            │
│  └───────────────────┘      │  • permissions      │            │
│                             │  • role_permissions │            │
│                             └─────────────────────┘            │
└────────────────────────────────────────────────────────────────┘
```

## Sierra ILS API Details

### Authentication Endpoint

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v6/users/validate` | POST | Validate Sierra staff login name + password |

**Request:**

```http
POST /iii/sierra-api/v6/users/validate
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "username": "jsmith",
  "password": "secretpassword"
}
```

**Response:**

- `204 No Content` - credentials valid
- `4xx` - invalid credentials or error

### Getting an Access Token

Sierra uses OAuth2 client credentials flow:

```http
POST /iii/sierra-api/v6/token
Authorization: Basic base64(client_key:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

**Response:**

```json
{
  "access_token": "abc123...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### Sierra API Key Requirements

- **Role needed:** Users Write
- Sierra admin creates API key via Sierra Administration app (requires permission 1052)
- Key provides: client key + client secret

### Documentation Links

- [Sierra REST API Tech Docs](https://techdocs.iii.com/sierraapi/Content/titlePage.htm)
- [Sierra User API](https://techdocs.iii.com/sierraapi/Content/zAPIs/userAPI.htm)
- [Administering Sierra API Client Keys](https://documentation.iii.com/sierrahelp/Content/sadmin/sadmin_other_webapps_api.html)

## Datasette Plugin Conventions

### Actor Structure

Datasette actors can be any shape, but conventions include:

```python
{
    "id": "jsmith",                    # String identifier (recommended)
    "display_name": "Jane Smith",      # Optional
    "roles": ["staff", "viewer"],      # Convention for role-based access
}
```

**Note:** `"roles"` is not baked into Datasette - it's a convention plugins implement.

### Key Plugin Hooks

1. **`actor_from_request(datasette, request)`** - Return actor dict from session cookie
2. **`permission_allowed(datasette, actor, action, resource)`** - Check if actor can perform action
3. **`asgi_wrapper(datasette)`** - Add login/logout routes

### Allow Blocks

Datasette permissions can match actor properties:

```yaml
# metadata.yml
databases:
  patrons:
    allow:
      roles: ["staff", "admin"]
```

### Documentation Links

- [Datasette Authentication and Permissions](https://docs.datasette.io/en/stable/authentication.html)
- [Datasette Plugin Hooks](https://docs.datasette.io/en/stable/plugin_hooks.html)
- [datasette-acl plugin](https://github.com/datasette/datasette-acl) (reference implementation)

## Database Schema

### `sierra_auth.db`

```sql
-- Users (auto-created on first successful Sierra login)
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    sierra_login TEXT UNIQUE NOT NULL,
    display_name TEXT,
    email TEXT,
    is_active BOOLEAN DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    last_login_at TEXT
);

-- Roles (seeded with defaults)
CREATE TABLE roles (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT 0  -- assigned to new users automatically
);

-- User-Role mapping (many-to-many)
CREATE TABLE user_roles (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TEXT DEFAULT (datetime('now')),
    granted_by INTEGER REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

-- Permissions (maps to Datasette permission actions)
CREATE TABLE permissions (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,      -- e.g., 'view-database-patrons'
    description TEXT
);

-- Role-Permission mapping (many-to-many)
CREATE TABLE role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Audit log (optional but recommended)
CREATE TABLE auth_log (
    id INTEGER PRIMARY KEY,
    timestamp TEXT DEFAULT (datetime('now')),
    sierra_login TEXT NOT NULL,
    event TEXT NOT NULL,  -- 'login_success', 'login_failure', 'logout', 'role_granted', etc.
    details TEXT          -- JSON blob for additional context
);
```

### Default Seed Data

```sql
-- Default roles
INSERT INTO roles (name, description, is_default) VALUES
    ('viewer', 'Can view public collection data only', 1),
    ('staff', 'Can view collection and patron data', 0),
    ('admin', 'Full access including user management', 0);

-- Default permissions
INSERT INTO permissions (name, description) VALUES
    ('view-instance', 'View Datasette instance'),
    ('view-database-collection', 'View collection database'),
    ('view-database-patrons', 'View patrons database'),
    ('execute-sql', 'Execute arbitrary SQL queries'),
    ('manage-users', 'Manage user roles and permissions');

-- Role-permission mappings
-- viewer: collection only
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'viewer' AND p.name IN ('view-instance', 'view-database-collection');

-- staff: collection + patrons
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'staff' AND p.name IN ('view-instance', 'view-database-collection', 'view-database-patrons');

-- admin: everything
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin';
```

## Plugin Structure

```
datasette-sierra-ils-auth/
├── pyproject.toml
├── README.md
├── LICENSE
├── CLAUDE.md                        # This specification document
├── datasette_sierra_ils_auth/
│   ├── __init__.py                  # Plugin registration & hooks
│   ├── auth_db.py                   # SQLite user/role management & migrations
│   ├── views.py                     # Login/logout/admin ASGI routes
│   └── templates/
│       ├── sierra_auth_login.html
│       ├── sierra_auth_error.html
│       ├── sierra_auth_admin_users.html
│       └── sierra_auth_admin_user_edit.html
└── tests/
    ├── conftest.py
    ├── test_sierra_ils_auth.py
    ├── test_auth_db.py
    ├── test_views.py
    └── test_hooks.py
```

**Note:** Sierra API client is provided by the `sierra-ils-utils` package dependency.

## Environment Variables

```bash
# Required
SIERRA_API_BASE=https://your-library.iii.com/iii/sierra-api/v6
SIERRA_CLIENT_KEY=your-api-key
SIERRA_CLIENT_SECRET=your-api-secret

# Recommended (required for admin UI access)
SIERRA_AUTH_ADMIN_PASSWORD=secure-password  # Creates local admin account

# Optional
SIERRA_AUTH_DB_PATH=sierra_auth.db          # Default: sierra_auth.db in current dir
SIERRA_AUTH_COOKIE_NAME=ds_sierra_auth      # Default: ds_sierra_auth
SIERRA_AUTH_COOKIE_MAX_AGE=86400            # Default: 86400 (24 hours)
SIERRA_AUTH_LOGIN_REDIRECT=/                # Default: / (home)
```

## Implementation Notes

### Login Flow

```python
async def handle_login(request, datasette):
    # 1. Parse form data
    form = await request.post_vars()
    sierra_login = form.get("username")
    password = form.get("password")

    # 2. Validate with Sierra
    sierra = SierraClient(
        base_url=os.environ["SIERRA_API_BASE"],
        client_key=os.environ["SIERRA_CLIENT_KEY"],
        client_secret=os.environ["SIERRA_CLIENT_SECRET"],
    )

    if not await sierra.validate_user(sierra_login, password):
        # Log failed attempt
        await auth_db.log_event(sierra_login, "login_failure")
        return Response.html(render_template("login.html", error="Invalid credentials"), status=401)

    # 3. Get or create local user
    auth_db = AuthDB(datasette)
    user = await auth_db.get_user(sierra_login)
    if not user:
        user = await auth_db.create_user(sierra_login)  # Gets default role(s)

    # 4. Update last login & log success
    await auth_db.update_last_login(user["id"])
    await auth_db.log_event(sierra_login, "login_success")

    # 5. Create signed session cookie
    response = Response.redirect(os.environ.get("SIERRA_AUTH_LOGIN_REDIRECT", "/"))
    response.set_cookie(
        COOKIE_NAME,
        datasette.sign({"id": user["sierra_login"], "ts": time.time()}, "sierra-auth"),
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response
```

### Actor from Request Hook

```python
@hookimpl
def actor_from_request(datasette, request):
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None

    try:
        payload = datasette.unsign(cookie, "sierra-auth")
    except BadSignature:
        return None

    # Check session age
    if time.time() - payload.get("ts", 0) > COOKIE_MAX_AGE:
        return None

    sierra_login = payload.get("id")
    if not sierra_login:
        return None

    # Fetch user with roles from local DB
    auth_db = AuthDB(datasette)
    user = auth_db.get_user_sync(sierra_login)
    if not user or not user["is_active"]:
        return None

    permissions = auth_db.get_user_permissions_sync(user["id"])

    return {
        "id": user["sierra_login"],
        "display_name": user["display_name"] or user["sierra_login"],
        "roles": user["roles"],
        "_permissions": permissions,  # Internal use for permission_allowed
    }
```

### Permission Allowed Hook

```python
@hookimpl
def permission_allowed(datasette, actor, action, resource):
    if actor is None:
        return False  # Deny anonymous for protected resources

    # Admins can do everything
    if "admin" in actor.get("roles", []):
        return True

    # Check specific permission
    permissions = actor.get("_permissions", [])

    # Build permission key
    if resource:
        permission_key = f"{action}-{resource}"
    else:
        permission_key = action

    if permission_key in permissions:
        return True

    # Return None to defer to other plugins/defaults
    return None
```

## Testing Strategy

1. **Unit tests for Sierra client** - Mock HTTP responses for token and validate endpoints
2. **Unit tests for auth_db** - Test user creation, role assignment, permission lookup
3. **Integration tests** - Full login flow with mocked Sierra API
4. **Permission tests** - Verify access control for different roles

## TODO

- [x] Create project scaffold with pyproject.toml
- [x] Implement Sierra API client for /v6/users/validate (via sierra-ils-utils)
- [x] Create sierra_auth.db schema with migrations
- [x] Implement login/logout ASGI routes
- [x] Implement actor_from_request hook with local DB lookup
- [x] Implement permission_allowed hook
- [x] Create login page template
- [x] Add user management admin UI
- [x] Write comprehensive tests (82% coverage)
- [x] Write README with setup instructions
- [ ] Publish to PyPI

## Related Projects

- [datasette-auth-github](https://github.com/simonw/datasette-auth-github) - OAuth example
- [datasette-auth-tokens](https://datasette.io/plugins/datasette-auth-tokens) - Token auth
- [datasette-auth-passwords](https://datasette.io/plugins/datasette-auth-passwords) - Password auth
- [datasette-acl](https://github.com/datasette/datasette-acl) - Advanced ACL management
