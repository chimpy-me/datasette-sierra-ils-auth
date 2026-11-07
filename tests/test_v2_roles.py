"""v0.2.0: no default role, seed_roles config, v1 -> v2 migration."""

import sqlite3

import pytest

from datasette_sierra_ils_auth.auth_db import AuthDB, SCHEMA_SQL, get_schema_version
from datasette_sierra_ils_auth import COOKIE_NAME
from datasette.utils.asgi import Forbidden
from datasette import hookimpl
from datasette.plugins import pm

from .helpers import ADMIN_PW, add_local_user, auth_db_for, make_ds, sign_in

pytestmark = pytest.mark.asyncio


async def test_first_sign_in_has_no_roles_and_no_permissions(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path)
    await ds.invoke_startup()
    add_local_user(tmp_path, "newperson", "pw")
    actor, _ = await sign_in(ds, "newperson", "pw")
    assert actor["roles"] == [] and actor["_permissions"] == []


async def test_first_login_through_login_view_creates_user_without_role(monkeypatch, tmp_path):
    """The create_user path: a Sierra-validated login with no user row yet."""
    from unittest.mock import AsyncMock, MagicMock, patch

    ds = make_ds(monkeypatch, tmp_path, plugin_config={"seed_roles": {"viewer": ["view-database-collection"]}})
    await ds.invoke_startup()
    sierra = MagicMock()
    sierra.async_request = AsyncMock(return_value=MagicMock(status_code=204))
    with patch("datasette_sierra_ils_auth.views.get_sierra_client", return_value=sierra):
        actor, _ = await sign_in(ds, "fresh", "pw")
    assert actor["roles"] == [] and actor["_permissions"] == []
    assert auth_db_for(tmp_path).get_user("fresh")["roles"] == []


async def test_viewer_default_is_opt_in(monkeypatch, tmp_path):
    from unittest.mock import AsyncMock, MagicMock, patch

    ds = make_ds(
        monkeypatch,
        tmp_path,
        plugin_config={
            "default_role": "viewer",
            "seed_roles": {"viewer": ["view-database-collection"], "reviewer": ["alt-review-edit"]},
        },
    )
    await ds.invoke_startup()
    sierra = MagicMock()
    sierra.async_request = AsyncMock(return_value=MagicMock(status_code=204))
    with patch("datasette_sierra_ils_auth.views.get_sierra_client", return_value=sierra):
        actor, _ = await sign_in(ds, "p2", "pw")
    assert actor["roles"] == ["viewer"]
    assert actor["_permissions"] == ["view-database-collection"]


async def test_seed_roles_creates_reviewer_with_permission(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path, plugin_config={"seed_roles": {"reviewer": ["alt-review-edit"]}})
    await ds.invoke_startup()
    db = auth_db_for(tmp_path)
    assert "reviewer" in [r["name"] for r in db.list_roles()]
    assert db.role_permissions("reviewer") == ["alt-review-edit"]


async def test_seed_is_idempotent_and_keeps_admin_grants(monkeypatch, tmp_path):
    cfg = {"seed_roles": {"reviewer": ["alt-review-edit"]}}
    ds = make_ds(monkeypatch, tmp_path, plugin_config=cfg)
    await ds.invoke_startup()
    db = auth_db_for(tmp_path)
    conn = db._connect()
    conn.execute("INSERT OR IGNORE INTO permissions (name) VALUES ('extra-grant')")
    conn.execute(
        "INSERT INTO role_permissions (role_id, permission_id) "
        "SELECT r.id, p.id FROM roles r, permissions p WHERE r.name='reviewer' AND p.name='extra-grant'"
    )
    conn.commit()
    conn.close()
    # invoke_startup() is once-per-instance, so boot a second instance on the same DB
    ds2 = make_ds(monkeypatch, tmp_path, plugin_config=cfg)
    await ds2.invoke_startup()
    assert db.role_permissions("reviewer") == ["alt-review-edit", "extra-grant"]
    assert [r["name"] for r in db.list_roles()].count("reviewer") == 1


async def test_fresh_v2_db_seeds_only_admin(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path)
    await ds.invoke_startup()
    db = auth_db_for(tmp_path)
    assert [r["name"] for r in db.list_roles()] == ["admin"]
    # no role other than admin holds view-instance (it would beat an instance allow:false)
    assert db.role_permissions("admin")  # admin has grants
    conn = db._connect()
    holders = [
        r[0]
        for r in conn.execute(
            "SELECT r.name FROM roles r JOIN role_permissions rp ON rp.role_id=r.id "
            "JOIN permissions p ON p.id=rp.permission_id WHERE p.name='view-instance'"
        )
    ]
    conn.close()
    assert holders == ["admin"]


async def test_seed_roles_view_instance_not_added_unless_configured(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path, plugin_config={"seed_roles": {"reviewer": ["alt-review-edit"]}})
    await ds.invoke_startup()
    assert "view-instance" not in auth_db_for(tmp_path).role_permissions("reviewer")


V1_SEED = """
INSERT INTO roles (name, description, is_default) VALUES
    ('viewer', 'v', 1), ('staff', 's', 0), ('admin', 'a', 0);
INSERT INTO permissions (name) VALUES ('view-instance'), ('manage-users');
INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, p.id FROM roles r, permissions p WHERE r.name='viewer' AND p.name='view-instance';
CREATE TABLE IF NOT EXISTS _schema_version (version INTEGER PRIMARY KEY);
INSERT INTO _schema_version VALUES (1);
"""


async def test_v1_database_migrates_to_v2(tmp_path):
    path = tmp_path / "v1.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_SQL)
    conn.executescript(V1_SEED)
    conn.execute("INSERT INTO users (sierra_login) VALUES ('old-user')")
    conn.execute("INSERT INTO user_roles (user_id, role_id) SELECT 1, id FROM roles WHERE name='viewer'")
    conn.commit()
    assert get_schema_version(conn) == 1
    conn.close()

    db = AuthDB(path)  # opens and migrates

    conn = sqlite3.connect(path)
    assert get_schema_version(conn) == 2
    conn.close()
    user = db.get_user("old-user")
    assert user["roles"] == ["viewer"]  # users and their grants kept
    roles = {r["name"]: r["is_default"] for r in db.list_roles()}
    assert set(roles) == {"viewer", "staff", "admin"}  # existing roles kept
    assert roles["viewer"] == 0  # no longer default
    assert db.role_permissions("viewer") == ["view-instance"]  # grants untouched


async def test_no_role_actor_on_forbidden_route_sees_no_role_page(monkeypatch, tmp_path):
    class Probe:
        __name__ = "probe_plugin"

        @staticmethod
        @hookimpl
        def register_routes():
            async def deny(datasette, request):
                raise Forbidden("nope")

            return [(r"^/probe-forbidden$", deny)]

    probe = Probe()
    pm.register(probe, name="probe_plugin")
    try:
        ds = make_ds(monkeypatch, tmp_path)
        await ds.invoke_startup()
        add_local_user(tmp_path, "newperson", "pw")
        _, cookie = await sign_in(ds, "newperson", "pw")
        r = await ds.client.get("/probe-forbidden", cookies={COOKIE_NAME: cookie})
        assert r.status_code == 403
        assert "signed in as newperson" in r.text
        assert "no role yet" in r.text
        assert "ask the administrator" in r.text

        # no actor: Datasette's own default 403 page, not ours
        anon = await ds.client.get("/probe-forbidden")
        assert anon.status_code == 403
        assert "no role yet" not in anon.text
        assert "nope" in anon.text

        # an actor with a role gets the default page, not the no-role one
        _, admin_cookie = await sign_in(ds, "admin", ADMIN_PW)
        ok = await ds.client.get("/probe-forbidden", cookies={COOKIE_NAME: admin_cookie})
        assert ok.status_code == 403
        assert "no role yet" not in ok.text
    finally:
        pm.unregister(name="probe_plugin")


@pytest.mark.parametrize("page", ["/-/sierra-auth/admin/users", "/-/sierra-auth/admin/users/1"])
async def test_admin_pages_no_role_user_sees_no_role_message(monkeypatch, tmp_path, page):
    ds = make_ds(monkeypatch, tmp_path)
    await ds.invoke_startup()
    add_local_user(tmp_path, "newperson", "pw")
    _, cookie = await sign_in(ds, "newperson", "pw")
    r = await ds.client.get(page, cookies={COOKIE_NAME: cookie})
    assert r.status_code == 403
    assert "signed in as newperson" in r.text and "no role yet" in r.text


async def test_admin_page_user_with_role_but_no_manage_gets_plain_denial(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path, plugin_config={"seed_roles": {"reviewer": ["alt-review-edit"]}})
    await ds.invoke_startup()
    add_local_user(tmp_path, "rev", "pw")
    db = auth_db_for(tmp_path)
    db.assign_role(db.get_user("rev")["id"], "reviewer")
    _, cookie = await sign_in(ds, "rev", "pw")
    r = await ds.client.get("/-/sierra-auth/admin/users", cookies={COOKIE_NAME: cookie})
    assert r.status_code == 403
    assert "do not have permission" in r.text and "no role yet" not in r.text


@pytest.mark.parametrize(
    "actor, expected",
    [
        (None, False),
        ({"id": "a", "roles": [], "_permissions": []}, True),
        ({"id": "a", "roles": ["r"], "_permissions": []}, False),
        ({"id": "a", "roles": [], "_permissions": ["p"]}, False),
        ({"id": "a", "roles": ["r"], "_permissions": ["p"]}, False),
    ],
)
async def test_has_no_role(actor, expected):
    from datasette_sierra_ils_auth import has_no_role

    assert has_no_role(actor) is expected


class _GuardedRoute:
    """Registers a route guarded by the (otherwise unrouted) require_permission."""

    __name__ = "guarded_probe"

    @staticmethod
    @hookimpl
    def register_routes():
        from datasette import Response
        from datasette_sierra_ils_auth.views import require_permission

        @require_permission("secret-perm")
        async def guarded(datasette, request):
            return Response.text("in")

        return [(r"^/probe-guarded$", guarded)]


async def test_require_permission_decorator_paths(monkeypatch, tmp_path):
    pm.register(_GuardedRoute(), name="guarded_probe")
    try:
        ds = make_ds(monkeypatch, tmp_path, settings={"base_url": "/alt-review/"})
        await ds.invoke_startup()
        add_local_user(tmp_path, "newperson", "pw")
        _, cookie = await sign_in(ds, "newperson", "pw")

        anon = await ds.client.get("/probe-guarded", follow_redirects=False)
        assert anon.headers["location"] == "/alt-review/-/sierra-auth/login"

        noperm = await ds.client.get("/probe-guarded", cookies={COOKIE_NAME: cookie})
        assert noperm.status_code == 403 and "no role yet" in noperm.text

        _, admin_cookie = await sign_in(ds, "admin", ADMIN_PW)
        ok = await ds.client.get("/probe-guarded", cookies={COOKIE_NAME: admin_cookie})
        assert ok.status_code == 200 and ok.text == "in"
    finally:
        pm.unregister(name="guarded_probe")
