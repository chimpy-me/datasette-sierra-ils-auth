"""Shared helpers for the v0.2.0 tests."""

import re
from pathlib import Path

from datasette.app import Datasette

from datasette_sierra_ils_auth import COOKIE_NAME
from datasette_sierra_ils_auth.auth_db import AuthDB

ADMIN_PW = "adminpw"


def make_ds(monkeypatch, tmp_path, plugin_config=None, settings=None):
    """A Datasette on a fresh auth DB; call `await ds.invoke_startup()` after."""
    for var in ("SIERRA_API_BASE", "SIERRA_CLIENT_KEY", "SIERRA_CLIENT_SECRET",
                "SIERRA_AUTH_LOGIN_REDIRECT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("SIERRA_AUTH_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("SIERRA_AUTH_ADMIN_PASSWORD", ADMIN_PW)
    metadata = {}
    if plugin_config is not None:
        metadata["plugins"] = {"datasette-sierra-ils-auth": plugin_config}
    return Datasette(memory=True, metadata=metadata, settings=settings or {})


def auth_db_for(tmp_path) -> AuthDB:
    return AuthDB(Path(tmp_path / "auth.db"))


def add_local_user(tmp_path, login, password):
    """A local-password account (no Sierra) with NO role, as a first sign-in would leave it."""
    db = auth_db_for(tmp_path)
    conn = db._connect()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO users (sierra_login, password_hash) VALUES (?, ?)",
            (login, AuthDB.hash_password(password)),
        )
        conn.commit()
    finally:
        conn.close()


def csrf(response):
    for cookie in response.cookies.jar:
        if cookie.name == "ds_csrftoken":
            return cookie.value


async def post_login(ds, username, password):
    page = await ds.client.get("/-/sierra-auth/login")
    return await ds.client.post(
        "/-/sierra-auth/login",
        data={"username": username, "password": password, "csrftoken": csrf(page)},
        follow_redirects=False,
    )


def session_cookie(response):
    for cookie in response.cookies.jar:
        if cookie.name == COOKIE_NAME:
            return cookie.value


async def sign_in(ds, username, password):
    """Sign in through the real login view; return the actor Datasette sees."""
    r = await post_login(ds, username, password)
    assert r.status_code == 302, r.text
    cookie = session_cookie(r)
    assert cookie
    actor = await ds.client.get("/-/actor.json", cookies={COOKIE_NAME: cookie})
    return actor.json()["actor"], cookie


def hrefs(html):
    return re.findall(r'href="([^"]*)"', html)
