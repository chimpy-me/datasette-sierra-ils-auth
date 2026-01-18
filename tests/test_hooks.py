"""Tests for plugin hooks - actor_from_request and permission_allowed."""

import pytest
from unittest.mock import MagicMock, patch
import tempfile
import time
from pathlib import Path

from datasette.app import Datasette

from datasette_sierra_ils_auth import (
    actor_from_request,
    permission_allowed,
    COOKIE_NAME,
    COOKIE_MAX_AGE,
)
from datasette_sierra_ils_auth.auth_db import AuthDB


@pytest.fixture
def temp_db_path():
    """Create a temporary database path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def auth_db(temp_db_path):
    """Create an AuthDB instance."""
    return AuthDB(Path(temp_db_path))


@pytest.fixture
def datasette_instance(temp_db_path):
    """Create a Datasette instance for testing."""
    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}, clear=True):
        ds = Datasette(memory=True)
        yield ds


class TestActorFromRequest:
    def test_returns_none_without_cookie(self, datasette_instance):
        """Should return None if no session cookie."""
        request = MagicMock()
        request.cookies = {}

        result = actor_from_request(datasette_instance, request)

        assert result is None

    def test_returns_none_for_invalid_cookie(self, datasette_instance):
        """Should return None for invalid/tampered cookie."""
        request = MagicMock()
        request.cookies = {COOKIE_NAME: "invalid-cookie-value"}

        result = actor_from_request(datasette_instance, request)

        assert result is None

    def test_returns_none_for_expired_session(self, datasette_instance, auth_db):
        """Should return None if session has expired."""
        # Create a user
        auth_db.create_user("testuser")

        # Create an expired cookie (timestamp in the past)
        payload = {"id": "testuser", "ts": time.time() - COOKIE_MAX_AGE - 1000}
        cookie = datasette_instance.sign(payload, "sierra-auth")

        request = MagicMock()
        request.cookies = {COOKIE_NAME: cookie}

        with patch("datasette_sierra_ils_auth.get_auth_db", return_value=auth_db):
            result = actor_from_request(datasette_instance, request)

        assert result is None

    def test_returns_none_for_inactive_user(self, datasette_instance, auth_db):
        """Should return None if user is inactive."""
        # Create user and deactivate
        user = auth_db.create_user("testuser")
        conn = auth_db._connect()
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user["id"],))
        conn.commit()
        conn.close()

        payload = {"id": "testuser", "ts": time.time()}
        cookie = datasette_instance.sign(payload, "sierra-auth")

        request = MagicMock()
        request.cookies = {COOKIE_NAME: cookie}

        with patch("datasette_sierra_ils_auth.get_auth_db", return_value=auth_db):
            result = actor_from_request(datasette_instance, request)

        assert result is None

    def test_returns_actor_for_valid_session(self, datasette_instance, auth_db):
        """Should return actor dict for valid session."""
        auth_db.create_user("testuser", "Test User")

        payload = {"id": "testuser", "ts": time.time()}
        cookie = datasette_instance.sign(payload, "sierra-auth")

        request = MagicMock()
        request.cookies = {COOKIE_NAME: cookie}

        with patch("datasette_sierra_ils_auth.get_auth_db", return_value=auth_db):
            result = actor_from_request(datasette_instance, request)

        assert result is not None
        assert result["id"] == "testuser"
        assert result["display_name"] == "Test User"
        assert "viewer" in result["roles"]
        assert "_permissions" in result

    def test_actor_includes_permissions(self, datasette_instance, auth_db):
        """Actor should include user's permissions."""
        auth_db.create_user("testuser")

        payload = {"id": "testuser", "ts": time.time()}
        cookie = datasette_instance.sign(payload, "sierra-auth")

        request = MagicMock()
        request.cookies = {COOKIE_NAME: cookie}

        with patch("datasette_sierra_ils_auth.get_auth_db", return_value=auth_db):
            result = actor_from_request(datasette_instance, request)

        assert "view-instance" in result["_permissions"]
        assert "view-database-collection" in result["_permissions"]


class TestPermissionAllowed:
    def test_returns_none_for_anonymous(self, datasette_instance):
        """Should return None for anonymous users (defer to defaults)."""
        result = permission_allowed(datasette_instance, None, "view-instance", None)

        assert result is None

    def test_admin_can_do_everything(self, datasette_instance):
        """Admin role should have all permissions."""
        actor = {"id": "admin", "roles": ["admin"], "_permissions": []}

        assert permission_allowed(datasette_instance, actor, "view-instance", None) is True
        assert permission_allowed(datasette_instance, actor, "execute-sql", None) is True
        assert permission_allowed(datasette_instance, actor, "manage-users", None) is True
        assert permission_allowed(datasette_instance, actor, "anything-else", None) is True

    def test_permission_check_without_resource(self, datasette_instance):
        """Should check permission without resource."""
        actor = {
            "id": "user",
            "roles": ["viewer"],
            "_permissions": ["view-instance"],
        }

        result = permission_allowed(datasette_instance, actor, "view-instance", None)

        assert result is True

    def test_permission_check_with_string_resource(self, datasette_instance):
        """Should check permission with string resource."""
        actor = {
            "id": "user",
            "roles": ["viewer"],
            "_permissions": ["view-database-collection"],
        }

        result = permission_allowed(datasette_instance, actor, "view-database", "collection")

        assert result is True

    def test_permission_check_with_tuple_resource(self, datasette_instance):
        """Should check permission with tuple resource."""
        actor = {
            "id": "user",
            "roles": ["viewer"],
            "_permissions": ["view-table-mydb-mytable"],
        }

        result = permission_allowed(datasette_instance, actor, "view-table", ("mydb", "mytable"))

        assert result is True

    def test_returns_none_for_missing_permission(self, datasette_instance):
        """Should return None if permission not found (defer to defaults)."""
        actor = {
            "id": "user",
            "roles": ["viewer"],
            "_permissions": ["view-instance"],
        }

        result = permission_allowed(datasette_instance, actor, "execute-sql", None)

        assert result is None

    def test_viewer_cannot_view_patrons(self, datasette_instance):
        """Viewer role should not have access to patrons database."""
        actor = {
            "id": "user",
            "roles": ["viewer"],
            "_permissions": ["view-instance", "view-database-collection"],
        }

        result = permission_allowed(datasette_instance, actor, "view-database", "patrons")

        assert result is None  # Defers (will be denied by default)
