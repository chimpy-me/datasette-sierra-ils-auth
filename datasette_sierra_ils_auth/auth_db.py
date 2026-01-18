"""
Local SQLite database for authorization (users, roles, permissions).
"""

import hashlib
import secrets
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS _schema_version (
    version INTEGER PRIMARY KEY
);

-- Users (auto-created on first successful Sierra login)
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    sierra_login TEXT UNIQUE NOT NULL,
    display_name TEXT,
    email TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    last_login_at TEXT,
    password_hash TEXT  -- For local-only accounts (e.g., built-in admin)
);

-- Roles (seeded with defaults)
CREATE TABLE roles (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    is_default INTEGER DEFAULT 0
);

-- User-Role mapping
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
    name TEXT UNIQUE NOT NULL,
    description TEXT
);

-- Role-Permission mapping
CREATE TABLE role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Audit log
CREATE TABLE auth_log (
    id INTEGER PRIMARY KEY,
    timestamp TEXT DEFAULT (datetime('now')),
    sierra_login TEXT NOT NULL,
    event TEXT NOT NULL,
    details TEXT
);
"""

SEED_SQL = """
-- Default roles
INSERT OR IGNORE INTO roles (name, description, is_default) VALUES
    ('viewer', 'Can view public collection data only', 1),
    ('staff', 'Can view collection and patron data', 0),
    ('admin', 'Full access including user management', 0);

-- Default permissions
INSERT OR IGNORE INTO permissions (name, description) VALUES
    ('view-instance', 'View Datasette instance'),
    ('view-database-collection', 'View collection database'),
    ('view-database-patrons', 'View patrons database'),
    ('execute-sql', 'Execute arbitrary SQL queries'),
    ('manage-users', 'Manage user roles and permissions');

-- viewer: collection only
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'viewer' AND p.name IN ('view-instance', 'view-database-collection');

-- staff: collection + patrons
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'staff' AND p.name IN ('view-instance', 'view-database-collection', 'view-database-patrons');

-- admin: everything
INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin';
"""


def get_schema_version(conn: sqlite3.Connection) -> int:
    """Get current schema version, or 0 if not initialized."""
    try:
        cursor = conn.execute("SELECT version FROM _schema_version LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0


def set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    """Set the schema version."""
    conn.execute("DELETE FROM _schema_version")
    conn.execute("INSERT INTO _schema_version (version) VALUES (?)", (version,))
    conn.commit()


def migrate(db_path: Path) -> None:
    """Run migrations to bring database up to current schema version."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        current = get_schema_version(conn)

        if current < 1:
            conn.executescript(SCHEMA_SQL)
            conn.executescript(SEED_SQL)
            set_schema_version(conn, 1)

        # Future migrations:
        # if current < 2:
        #     conn.execute("ALTER TABLE ...")
        #     set_schema_version(conn, 2)
    finally:
        conn.close()


class AuthDB:
    """Interface for auth database operations."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        migrate(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_user(self, sierra_login: str) -> dict | None:
        """Get user by Sierra login name."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT * FROM users WHERE sierra_login = ?",
                (sierra_login,)
            )
            row = cursor.fetchone()
            if not row:
                return None

            user = dict(row)
            user["roles"] = self._get_user_roles(conn, user["id"])
            return user
        finally:
            conn.close()

    def _get_user_roles(self, conn: sqlite3.Connection, user_id: int) -> list[str]:
        """Get role names for a user."""
        cursor = conn.execute("""
            SELECT r.name FROM roles r
            JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = ?
        """, (user_id,))
        return [row["name"] for row in cursor.fetchall()]

    def create_user(self, sierra_login: str, display_name: str | None = None) -> dict:
        """Create a new user with default roles."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                "INSERT INTO users (sierra_login, display_name) VALUES (?, ?)",
                (sierra_login, display_name)
            )
            user_id = cursor.lastrowid

            # Assign default roles
            conn.execute("""
                INSERT INTO user_roles (user_id, role_id)
                SELECT ?, id FROM roles WHERE is_default = 1
            """, (user_id,))

            conn.commit()
            return self.get_user(sierra_login)
        finally:
            conn.close()

    def update_last_login(self, user_id: int) -> None:
        """Update user's last login timestamp."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE users SET last_login_at = datetime('now') WHERE id = ?",
                (user_id,)
            )
            conn.commit()
        finally:
            conn.close()

    def get_user_permissions(self, user_id: int) -> list[str]:
        """Get all permission names for a user (via their roles)."""
        conn = self._connect()
        try:
            cursor = conn.execute("""
                SELECT DISTINCT p.name FROM permissions p
                JOIN role_permissions rp ON rp.permission_id = p.id
                JOIN user_roles ur ON ur.role_id = rp.role_id
                WHERE ur.user_id = ?
            """, (user_id,))
            return [row["name"] for row in cursor.fetchall()]
        finally:
            conn.close()

    def log_event(self, sierra_login: str, event: str, details: str | None = None) -> None:
        """Log an auth event."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO auth_log (sierra_login, event, details) VALUES (?, ?, ?)",
                (sierra_login, event, details)
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password with a random salt using SHA-256."""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.sha256((salt + password).encode())
        return f"{salt}${hash_obj.hexdigest()}"

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against a hash."""
        if not password_hash or "$" not in password_hash:
            return False
        salt, stored_hash = password_hash.split("$", 1)
        hash_obj = hashlib.sha256((salt + password).encode())
        return hash_obj.hexdigest() == stored_hash

    def create_or_update_admin(self, password: str) -> dict:
        """Create or update the built-in admin account."""
        conn = self._connect()
        try:
            password_hash = self.hash_password(password)

            # Check if admin exists
            cursor = conn.execute(
                "SELECT id FROM users WHERE sierra_login = 'admin'"
            )
            existing = cursor.fetchone()

            if existing:
                # Update password
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE sierra_login = 'admin'",
                    (password_hash,)
                )
            else:
                # Create admin user
                cursor = conn.execute(
                    "INSERT INTO users (sierra_login, display_name, password_hash) VALUES (?, ?, ?)",
                    ("admin", "Administrator", password_hash)
                )
                user_id = cursor.lastrowid

                # Assign admin role
                conn.execute("""
                    INSERT INTO user_roles (user_id, role_id)
                    SELECT ?, id FROM roles WHERE name = 'admin'
                """, (user_id,))

            conn.commit()
            return self.get_user("admin")
        finally:
            conn.close()

    def check_local_password(self, sierra_login: str, password: str) -> bool:
        """Check if a user has a local password and if it matches."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT password_hash FROM users WHERE sierra_login = ?",
                (sierra_login,)
            )
            row = cursor.fetchone()
            if not row or not row["password_hash"]:
                return False
            return self.verify_password(password, row["password_hash"])
        finally:
            conn.close()

    # Admin methods for user/role management

    def list_users(self) -> list[dict]:
        """List all users with their roles."""
        conn = self._connect()
        try:
            cursor = conn.execute("""
                SELECT id, sierra_login, display_name, email, is_active,
                       created_at, last_login_at
                FROM users ORDER BY sierra_login
            """)
            users = []
            for row in cursor.fetchall():
                user = dict(row)
                user["roles"] = self._get_user_roles(conn, user["id"])
                users.append(user)
            return users
        finally:
            conn.close()

    def list_roles(self) -> list[dict]:
        """List all available roles."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT id, name, description, is_default FROM roles ORDER BY name"
            )
            return [dict(row) for row in cursor.fetchall()]
        finally:
            conn.close()

    def assign_role(self, user_id: int, role_name: str, granted_by: int | None = None) -> bool:
        """Assign a role to a user. Returns True if role was assigned."""
        conn = self._connect()
        try:
            # Get role id
            cursor = conn.execute(
                "SELECT id FROM roles WHERE name = ?", (role_name,)
            )
            role = cursor.fetchone()
            if not role:
                return False

            # Check if already assigned
            cursor = conn.execute(
                "SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ?",
                (user_id, role["id"])
            )
            if cursor.fetchone():
                return False  # Already has role

            conn.execute(
                "INSERT INTO user_roles (user_id, role_id, granted_by) VALUES (?, ?, ?)",
                (user_id, role["id"], granted_by)
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def remove_role(self, user_id: int, role_name: str) -> bool:
        """Remove a role from a user. Returns True if role was removed."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT id FROM roles WHERE name = ?", (role_name,)
            )
            role = cursor.fetchone()
            if not role:
                return False

            cursor = conn.execute(
                "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
                (user_id, role["id"])
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def set_user_active(self, user_id: int, is_active: bool) -> None:
        """Activate or deactivate a user."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE users SET is_active = ? WHERE id = ?",
                (1 if is_active else 0, user_id)
            )
            conn.commit()
        finally:
            conn.close()

    def get_user_by_id(self, user_id: int) -> dict | None:
        """Get user by ID."""
        conn = self._connect()
        try:
            cursor = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            user = dict(row)
            user["roles"] = self._get_user_roles(conn, user["id"])
            return user
        finally:
            conn.close()
