"""v0.2.0: every redirect and link honours base_url."""

import pytest

from datasette_sierra_ils_auth import COOKIE_NAME, menu_links

from .helpers import ADMIN_PW, auth_db_for, hrefs, make_ds, post_login, sign_in

pytestmark = pytest.mark.asyncio

BASE = {"base_url": "/alt-review/"}


async def test_login_success_redirects_under_base_url(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path, settings=BASE)
    await ds.invoke_startup()
    r = await post_login(ds, "admin", ADMIN_PW)
    assert r.headers["location"] == "/alt-review/"


async def test_login_redirect_env_is_relative_to_base_url(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path, settings=BASE)
    monkeypatch.setenv("SIERRA_AUTH_LOGIN_REDIRECT", "/review/queue")
    await ds.invoke_startup()
    r = await post_login(ds, "admin", ADMIN_PW)
    assert r.headers["location"] == "/alt-review/review/queue"


async def test_logout_and_admin_bounce_stay_under_base_url(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path, settings=BASE)
    await ds.invoke_startup()
    out = await ds.client.get("/-/sierra-auth/logout", follow_redirects=False)
    assert out.headers["location"] == "/alt-review/"
    for page in ("/-/sierra-auth/admin/users", "/-/sierra-auth/admin/users/1"):
        r = await ds.client.get(page, follow_redirects=False)
        assert r.headers["location"] == "/alt-review/-/sierra-auth/login"


async def test_every_link_on_admin_and_error_pages_is_under_base_url(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path, settings=BASE)
    await ds.invoke_startup()
    uid = auth_db_for(tmp_path).get_user("admin")["id"]
    _, cookie = await sign_in(ds, "admin", ADMIN_PW)
    pages = ["/-/sierra-auth/admin/users", f"/-/sierra-auth/admin/users/{uid}",
             "/-/sierra-auth/admin/users/9999"]  # last one renders the error page
    for page in pages:
        html = (await ds.client.get(page, cookies={COOKIE_NAME: cookie})).text
        found = [h for h in hrefs(html) if h.startswith("/")]
        assert found, page
        assert all(h.startswith("/alt-review/") for h in found), (page, found)

    admin_actor = {"id": "admin", "roles": ["admin"], "_permissions": []}
    menu = [l["href"] for l in menu_links(ds, actor=admin_actor, request=None)]
    assert len(menu) == 2 and all(h.startswith("/alt-review/") for h in menu)
    anon = [l["href"] for l in menu_links(ds, actor=None, request=None)]
    assert anon == ["/alt-review/-/sierra-auth/login"]
