import pytest
from datasette_sierra_ils_auth import COOKIE_NAME
from .helpers import ADMIN_PW, make_ds, post_login


@pytest.mark.asyncio
async def test_session_cookie_is_secure_httponly_lax(monkeypatch, tmp_path):
    ds = make_ds(monkeypatch, tmp_path)
    await ds.invoke_startup()
    r = await post_login(ds, "admin", ADMIN_PW)
    assert r.status_code == 302
    ours = [h for h in r.headers.get_list("set-cookie") if h.startswith(COOKIE_NAME + "=")]
    assert len(ours) == 1
    flags = ours[0].lower()
    assert "secure" in flags and "httponly" in flags and "samesite=lax" in flags
