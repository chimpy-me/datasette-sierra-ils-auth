"""
Datasette plugin for authenticating staff users against Sierra ILS REST API.
"""

import os
import time
from pathlib import Path

from datasette import hookimpl
from itsdangerous import BadSignature
from sierra_ils_utils import SierraAPI

from .auth_db import AuthDB

COOKIE_NAME = os.environ.get("SIERRA_AUTH_COOKIE_NAME", "ds_sierra_auth")
COOKIE_MAX_AGE = int(os.environ.get("SIERRA_AUTH_COOKIE_MAX_AGE", 86400))


def get_auth_db(datasette) -> AuthDB:
    """Get or create AuthDB instance."""
    db_path = os.environ.get("SIERRA_AUTH_DB_PATH")
    if not db_path:
        # Default to current working directory
        db_path = Path.cwd() / "sierra_auth.db"
    return AuthDB(Path(db_path))


def get_sierra_client(datasette) -> SierraAPI | None:
    """Get the shared Sierra API client, or None if not configured."""
    return getattr(datasette, "_sierra_client", None)


@hookimpl
def startup(datasette):
    """Initialize the Sierra API client and admin account on startup."""
    base_url = os.environ.get("SIERRA_API_BASE")
    client_key = os.environ.get("SIERRA_CLIENT_KEY")
    client_secret = os.environ.get("SIERRA_CLIENT_SECRET")

    if all([base_url, client_key, client_secret]):
        datasette._sierra_client = SierraAPI(
            base_url=base_url,
            client_id=client_key,
            client_secret=client_secret,
        )
    else:
        datasette._sierra_client = None

    # Create/update built-in admin account if password is configured
    admin_password = os.environ.get("SIERRA_AUTH_ADMIN_PASSWORD")
    if admin_password:
        auth_db = get_auth_db(datasette)
        auth_db.create_or_update_admin(admin_password)


@hookimpl
def actor_from_request(datasette, request):
    """Build actor from session cookie and local auth database."""
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
    auth_db = get_auth_db(datasette)
    user = auth_db.get_user(sierra_login)
    if not user or not user["is_active"]:
        return None

    permissions = auth_db.get_user_permissions(user["id"])

    return {
        "id": user["sierra_login"],
        "display_name": user["display_name"] or user["sierra_login"],
        "roles": user["roles"],
        "_permissions": permissions,
    }


@hookimpl
def permission_allowed(datasette, actor, action, resource):
    """Check if actor has permission for the given action."""
    if actor is None:
        return None  # Defer to other plugins/defaults

    # Admins can do everything
    if "admin" in actor.get("roles", []):
        return True

    permissions = actor.get("_permissions", [])

    # Build permission key
    if resource:
        if isinstance(resource, str):
            permission_key = f"{action}-{resource}"
        else:
            # resource might be a tuple like (database, table)
            permission_key = f"{action}-{'-'.join(str(r) for r in resource)}"
    else:
        permission_key = action

    if permission_key in permissions:
        return True

    # Return None to defer to other plugins/defaults
    return None


@hookimpl
def register_routes():
    """Register login/logout and admin routes."""
    from .views import login, logout, admin_users, admin_user_edit

    return [
        (r"^/-/sierra-auth/login$", login),
        (r"^/-/sierra-auth/logout$", logout),
        (r"^/-/sierra-auth/admin/users$", admin_users),
        (r"^/-/sierra-auth/admin/users/(?P<user_id>\d+)$", admin_user_edit),
    ]


@hookimpl
def menu_links(datasette, actor, request):
    """Add login/logout and admin links to the menu."""
    if actor:
        links = []
        # Add admin link if user has permission
        if "admin" in actor.get("roles", []) or "manage-users" in actor.get("_permissions", []):
            links.append({"href": "/-/sierra-auth/admin/users", "label": "Manage users"})
        links.append({"href": "/-/sierra-auth/logout", "label": "Log out"})
        return links
    else:
        return [
            {"href": "/-/sierra-auth/login", "label": "Log in"},
        ]
