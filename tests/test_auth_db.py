"""Tests for auth_db.py - schema, user CRUD, and permissions."""

import pytest
from pathlib import Path
import tempfile
import sqlite3

from datasette_sierra_ils_auth.auth_db import (
    AuthDB,
    migrate,
    get_schema_version,
    SCHEMA_VERSION,
)


@pytest.fixture
def db_path():
    """Create a temporary database file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield Path(f.name)
    # Cleanup
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def auth_db(db_path):
    """Create an AuthDB instance with a fresh database."""
    return AuthDB(db_path)


class TestMigration:
    def test_migrate_creates_schema(self, db_path):
        """Migration should create all tables and set schema version."""
        migrate(db_path)

        conn = sqlite3.connect(db_path)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row[0] for row in cursor.fetchall()}
        conn.close()

        expected_tables = {
            "_schema_version",
            "users",
            "roles",
            "user_roles",
            "permissions",
            "role_permissions",
            "auth_log",
        }
        assert expected_tables.issubset(tables)

    def test_migrate_sets_schema_version(self, db_path):
        """Migration should set the schema version."""
        migrate(db_path)

        conn = sqlite3.connect(db_path)
        version = get_schema_version(conn)
        conn.close()

        assert version == SCHEMA_VERSION

    def test_migrate_seeds_default_roles(self, db_path):
        """Migration should seed default roles."""
        migrate(db_path)

        conn = sqlite3.connect(db_path)
        cursor = conn.execute("SELECT name FROM roles ORDER BY name")
        roles = [row[0] for row in cursor.fetchall()]
        conn.close()

        assert "viewer" in roles
        assert "staff" in roles
        assert "admin" in roles

    def test_migrate_seeds_default_permissions(self, db_path):
        """Migration should seed default permissions."""
        migrate(db_path)

        conn = sqlite3.connect(db_path)
        cursor = conn.execute("SELECT name FROM permissions ORDER BY name")
        permissions = [row[0] for row in cursor.fetchall()]
        conn.close()

        assert "view-instance" in permissions
        assert "view-database-collection" in permissions
        assert "view-database-patrons" in permissions
        assert "execute-sql" in permissions
        assert "manage-users" in permissions

    def test_migrate_is_idempotent(self, db_path):
        """Running migration multiple times should be safe."""
        migrate(db_path)
        migrate(db_path)
        migrate(db_path)

        conn = sqlite3.connect(db_path)
        version = get_schema_version(conn)
        cursor = conn.execute("SELECT COUNT(*) FROM roles")
        role_count = cursor.fetchone()[0]
        conn.close()

        assert version == SCHEMA_VERSION
        assert role_count == 3  # Still just 3 roles


class TestAuthDBUsers:
    def test_get_user_returns_none_for_nonexistent(self, auth_db):
        """get_user should return None for nonexistent user."""
        user = auth_db.get_user("nonexistent")
        assert user is None

    def test_create_user(self, auth_db):
        """create_user should create a user with default roles."""
        user = auth_db.create_user("testuser", "Test User")

        assert user is not None
        assert user["sierra_login"] == "testuser"
        assert user["display_name"] == "Test User"
        assert user["is_active"] == 1
        assert "viewer" in user["roles"]  # Default role

    def test_create_user_without_display_name(self, auth_db):
        """create_user should work without display name."""
        user = auth_db.create_user("testuser")

        assert user["sierra_login"] == "testuser"
        assert user["display_name"] is None

    def test_get_user_returns_user_with_roles(self, auth_db):
        """get_user should return user with their roles."""
        auth_db.create_user("testuser")
        user = auth_db.get_user("testuser")

        assert user is not None
        assert "roles" in user
        assert isinstance(user["roles"], list)
        assert "viewer" in user["roles"]

    def test_create_duplicate_user_fails(self, auth_db):
        """Creating a duplicate user should raise an error."""
        auth_db.create_user("testuser")

        with pytest.raises(sqlite3.IntegrityError):
            auth_db.create_user("testuser")

    def test_update_last_login(self, auth_db):
        """update_last_login should set the timestamp."""
        user = auth_db.create_user("testuser")
        assert user["last_login_at"] is None

        auth_db.update_last_login(user["id"])
        updated_user = auth_db.get_user("testuser")

        assert updated_user["last_login_at"] is not None


class TestAuthDBPermissions:
    def test_get_user_permissions_for_viewer(self, auth_db):
        """Viewer role should have limited permissions."""
        user = auth_db.create_user("testuser")
        permissions = auth_db.get_user_permissions(user["id"])

        assert "view-instance" in permissions
        assert "view-database-collection" in permissions
        assert "view-database-patrons" not in permissions
        assert "execute-sql" not in permissions

    def test_admin_has_all_permissions(self, auth_db):
        """Admin role should have all permissions."""
        # Create user and manually assign admin role
        user = auth_db.create_user("adminuser")

        conn = auth_db._connect()
        conn.execute("""
            INSERT INTO user_roles (user_id, role_id)
            SELECT ?, id FROM roles WHERE name = 'admin'
        """, (user["id"],))
        conn.commit()
        conn.close()

        permissions = auth_db.get_user_permissions(user["id"])

        assert "view-instance" in permissions
        assert "view-database-collection" in permissions
        assert "view-database-patrons" in permissions
        assert "execute-sql" in permissions
        assert "manage-users" in permissions


class TestAuthDBLogging:
    def test_log_event(self, auth_db):
        """log_event should create an audit log entry."""
        auth_db.log_event("testuser", "login_success")

        conn = auth_db._connect()
        cursor = conn.execute(
            "SELECT sierra_login, event FROM auth_log WHERE sierra_login = ?",
            ("testuser",)
        )
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row["sierra_login"] == "testuser"
        assert row["event"] == "login_success"

    def test_log_event_with_details(self, auth_db):
        """log_event should store details."""
        auth_db.log_event("testuser", "login_failure", "Invalid password")

        conn = auth_db._connect()
        cursor = conn.execute(
            "SELECT details FROM auth_log WHERE sierra_login = ?",
            ("testuser",)
        )
        row = cursor.fetchone()
        conn.close()

        assert row["details"] == "Invalid password"


class TestAuthDBPassword:
    def test_hash_password_returns_salted_hash(self, auth_db):
        """hash_password should return salt$hash format."""
        hashed = auth_db.hash_password("secret123")

        assert "$" in hashed
        parts = hashed.split("$")
        assert len(parts) == 2
        assert len(parts[0]) == 32  # 16 bytes hex = 32 chars
        assert len(parts[1]) == 64  # SHA-256 hex = 64 chars

    def test_hash_password_unique_per_call(self, auth_db):
        """Each hash should have a unique salt."""
        hash1 = auth_db.hash_password("secret123")
        hash2 = auth_db.hash_password("secret123")

        assert hash1 != hash2  # Different salts

    def test_verify_password_correct(self, auth_db):
        """verify_password should return True for correct password."""
        hashed = auth_db.hash_password("secret123")

        assert auth_db.verify_password("secret123", hashed) is True

    def test_verify_password_incorrect(self, auth_db):
        """verify_password should return False for wrong password."""
        hashed = auth_db.hash_password("secret123")

        assert auth_db.verify_password("wrongpassword", hashed) is False

    def test_verify_password_invalid_hash(self, auth_db):
        """verify_password should return False for invalid hash."""
        assert auth_db.verify_password("secret", "") is False
        assert auth_db.verify_password("secret", "nohashhere") is False
        assert auth_db.verify_password("secret", None) is False


class TestAuthDBAdminAccount:
    def test_create_admin_creates_user(self, auth_db):
        """create_or_update_admin should create admin user."""
        admin = auth_db.create_or_update_admin("adminpass")

        assert admin is not None
        assert admin["sierra_login"] == "admin"
        assert admin["display_name"] == "Administrator"
        assert "admin" in admin["roles"]

    def test_create_admin_sets_password(self, auth_db):
        """create_or_update_admin should set password hash."""
        auth_db.create_or_update_admin("adminpass")

        conn = auth_db._connect()
        cursor = conn.execute(
            "SELECT password_hash FROM users WHERE sierra_login = 'admin'"
        )
        row = cursor.fetchone()
        conn.close()

        assert row["password_hash"] is not None
        assert auth_db.verify_password("adminpass", row["password_hash"])

    def test_update_admin_changes_password(self, auth_db):
        """create_or_update_admin should update password if admin exists."""
        auth_db.create_or_update_admin("oldpass")
        auth_db.create_or_update_admin("newpass")

        assert auth_db.check_local_password("admin", "newpass") is True
        assert auth_db.check_local_password("admin", "oldpass") is False

    def test_check_local_password_works(self, auth_db):
        """check_local_password should validate admin credentials."""
        auth_db.create_or_update_admin("adminpass")

        assert auth_db.check_local_password("admin", "adminpass") is True
        assert auth_db.check_local_password("admin", "wrongpass") is False

    def test_check_local_password_nonexistent_user(self, auth_db):
        """check_local_password should return False for nonexistent user."""
        assert auth_db.check_local_password("nobody", "anypass") is False

    def test_check_local_password_user_without_password(self, auth_db):
        """check_local_password should return False if user has no password."""
        auth_db.create_user("sierrauser")  # No local password

        assert auth_db.check_local_password("sierrauser", "anypass") is False


class TestAuthDBAdminMethods:
    def test_list_users(self, auth_db):
        """list_users should return all users with roles."""
        auth_db.create_user("user1", "User One")
        auth_db.create_user("user2", "User Two")

        users = auth_db.list_users()

        assert len(users) == 2
        logins = [u["sierra_login"] for u in users]
        assert "user1" in logins
        assert "user2" in logins
        # Each user should have roles
        for user in users:
            assert "roles" in user

    def test_list_roles(self, auth_db):
        """list_roles should return all available roles."""
        roles = auth_db.list_roles()

        role_names = [r["name"] for r in roles]
        assert "viewer" in role_names
        assert "staff" in role_names
        assert "admin" in role_names

    def test_assign_role(self, auth_db):
        """assign_role should add a role to a user."""
        user = auth_db.create_user("testuser")
        assert "staff" not in user["roles"]

        result = auth_db.assign_role(user["id"], "staff")

        assert result is True
        updated_user = auth_db.get_user("testuser")
        assert "staff" in updated_user["roles"]

    def test_assign_role_already_assigned(self, auth_db):
        """assign_role should return False if role already assigned."""
        user = auth_db.create_user("testuser")
        # User already has viewer role by default

        result = auth_db.assign_role(user["id"], "viewer")

        assert result is False

    def test_assign_role_nonexistent_role(self, auth_db):
        """assign_role should return False for nonexistent role."""
        user = auth_db.create_user("testuser")

        result = auth_db.assign_role(user["id"], "nonexistent")

        assert result is False

    def test_remove_role(self, auth_db):
        """remove_role should remove a role from a user."""
        user = auth_db.create_user("testuser")
        assert "viewer" in user["roles"]

        result = auth_db.remove_role(user["id"], "viewer")

        assert result is True
        updated_user = auth_db.get_user("testuser")
        assert "viewer" not in updated_user["roles"]

    def test_remove_role_not_assigned(self, auth_db):
        """remove_role should return False if role not assigned."""
        user = auth_db.create_user("testuser")

        result = auth_db.remove_role(user["id"], "admin")

        assert result is False

    def test_remove_role_nonexistent_role(self, auth_db):
        """remove_role should return False for nonexistent role."""
        user = auth_db.create_user("testuser")

        result = auth_db.remove_role(user["id"], "nonexistent")

        assert result is False

    def test_set_user_active(self, auth_db):
        """set_user_active should change user's active status."""
        user = auth_db.create_user("testuser")
        assert user["is_active"] == 1

        auth_db.set_user_active(user["id"], False)

        updated_user = auth_db.get_user("testuser")
        assert updated_user["is_active"] == 0

        auth_db.set_user_active(user["id"], True)

        updated_user = auth_db.get_user("testuser")
        assert updated_user["is_active"] == 1

    def test_get_user_by_id(self, auth_db):
        """get_user_by_id should return user with roles."""
        created = auth_db.create_user("testuser", "Test User")

        user = auth_db.get_user_by_id(created["id"])

        assert user is not None
        assert user["sierra_login"] == "testuser"
        assert user["display_name"] == "Test User"
        assert "roles" in user

    def test_get_user_by_id_nonexistent(self, auth_db):
        """get_user_by_id should return None for nonexistent user."""
        user = auth_db.get_user_by_id(99999)

        assert user is None
