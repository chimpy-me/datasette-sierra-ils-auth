"""Failed sign-in cap and sierra_status logging."""

import sqlite3
from unittest.mock import patch

import pytest

from datasette_sierra_ils_auth.throttle import Throttle

from .helpers import ADMIN_PW, auth_db_for, make_ds, post_login

pytestmark = pytest.mark.asyncio


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class StubSierra:
    def __init__(self, status=400, body=None):
        self.status, self.body, self.calls = status, body, 0

    async def async_request(self, method, path, json=None):
        self.calls += 1
        return FakeResponse(self.status, self.body)


BAD = {"code": 108, "specificCode": 0, "httpStatus": 400, "name": "Invalid credentials"}


async def setup(monkeypatch, tmp_path, plugin_config=None):
    ds = make_ds(monkeypatch, tmp_path, plugin_config=plugin_config)
    await ds.invoke_startup()
    return ds


def stubbed(stub):
    return patch("datasette_sierra_ils_auth.views.get_sierra_client", return_value=stub)


def log_rows(tmp_path):
    conn = sqlite3.connect(tmp_path / "auth.db")
    try:
        return conn.execute("SELECT sierra_login, event, details FROM auth_log ORDER BY id").fetchall()
    finally:
        conn.close()


async def test_sixth_failure_is_refused_without_calling_sierra(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path)
    with stubbed(stub):
        for _ in range(5):
            assert (await post_login(ds, "zzz-probe", "bad")).status_code == 401
        r = await post_login(ds, "zzz-probe", "bad")
    assert r.status_code == 429
    assert "Too many failed sign-in attempts; try again in 15 minutes" in r.text
    assert stub.calls == 5
    throttled = [row for row in log_rows(tmp_path) if row[1] == "login_throttled"]
    assert len(throttled) == 1 and throttled[0][0] == "zzz-probe"
    assert "bad" not in (throttled[0][2] or "").replace("address", "")


async def test_throttled_attempt_skips_local_password_check_too(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path)
    with stubbed(stub):
        for _ in range(5):
            await post_login(ds, "admin", "wrong")
        r = await post_login(ds, "admin", ADMIN_PW)  # correct local password, still refused
    assert r.status_code == 429


async def test_cap_is_per_address_too(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path)
    with stubbed(stub):
        for n in range(5):
            assert (await post_login(ds, f"user{n}", "bad")).status_code == 401
        r = await post_login(ds, "user-new", "bad")
    assert r.status_code == 429 and stub.calls == 5


async def test_forged_forwarded_for_does_not_reset_the_cap(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path, plugin_config={"trust_forwarded": True})
    with stubbed(stub):
        for n in range(5):
            r = await post_login(ds, f"user{n}", "bad",
                                 headers={"X-Forwarded-For": f"10.0.0.{n}, 100.64.0.9"})
            assert r.status_code == 401
        r = await post_login(ds, "user-new", "bad",
                             headers={"X-Forwarded-For": "10.0.0.99, 100.64.0.9"})
    assert r.status_code == 429


async def test_forwarded_for_is_ignored_unless_trusted(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path)  # trust_forwarded off
    with stubbed(stub):
        for n in range(5):
            await post_login(ds, f"user{n}", "bad", headers={"X-Forwarded-For": f"10.0.0.{n}"})
        r = await post_login(ds, "user-new", "bad", headers={"X-Forwarded-For": "10.0.0.77"})
    assert r.status_code == 429


async def test_username_cap_holds_across_addresses_through_the_view(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path, plugin_config={"trust_forwarded": True})
    with stubbed(stub):
        for n in range(5):
            r = await post_login(ds, "Foo", "bad", headers={"X-Forwarded-For": f"10.0.0.{n}"})
            assert r.status_code == 401
        # a sixth attempt, new address, differently cased and padded name
        r = await post_login(ds, "  fOO ", "bad", headers={"X-Forwarded-For": "10.0.0.9"})
    assert r.status_code == 429 and stub.calls == 5


async def test_other_username_from_a_used_address_is_not_blocked(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path, plugin_config={"trust_forwarded": True})
    with stubbed(stub):
        for n in range(5):
            await post_login(ds, "Foo", "bad", headers={"X-Forwarded-For": f"10.0.0.{n}"})
        r = await post_login(ds, "Bar", "bad", headers={"X-Forwarded-For": "10.0.0.1"})
    assert r.status_code == 401 and stub.calls == 6


async def test_trusted_distinct_last_hops_are_distinct_addresses(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path, plugin_config={"trust_forwarded": True})
    with stubbed(stub):
        for n in range(5):
            await post_login(ds, f"user{n}", "bad", headers={"X-Forwarded-For": "1.1.1.1"})
        r = await post_login(ds, "other", "bad", headers={"X-Forwarded-For": "2.2.2.2"})
    assert r.status_code == 401


async def test_non_204_status_is_logged(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path)
    with stubbed(stub):
        await post_login(ds, "zzz-probe", "hunter2-secret")
    details = [r[2] for r in log_rows(tmp_path) if r[1] == "login_failure"]
    assert any("sierra_status=400" in d and "code=108" in d for d in details)
    assert not any("hunter2-secret" in (d or "") for _, _, d in log_rows(tmp_path))


async def test_non_204_without_json_body_logs_status_only(monkeypatch, tmp_path):
    stub = StubSierra(500, None)
    ds = await setup(monkeypatch, tmp_path)
    with stubbed(stub):
        r = await post_login(ds, "zzz-probe", "bad")
    assert r.status_code == 401
    details = [r[2] for r in log_rows(tmp_path) if r[1] == "login_failure"]
    assert any("sierra_status=500" in d and "code=" not in d for d in details)


async def test_window_expires(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path)
    now = [1000.0]
    ds._sierra_throttle = Throttle(clock=lambda: now[0])
    with stubbed(stub):
        for _ in range(5):
            await post_login(ds, "zzz-probe", "bad")
        assert (await post_login(ds, "zzz-probe", "bad")).status_code == 429
        now[0] += 899
        assert (await post_login(ds, "zzz-probe", "bad")).status_code == 429
        now[0] += 2
        assert (await post_login(ds, "zzz-probe", "bad")).status_code == 401


async def test_case_folded_username(monkeypatch, tmp_path):
    t = Throttle(limit=2)
    t.record_failure("ZZZ-Probe", "a1")
    t.record_failure("zzz-probe", "a2")
    assert t.blocked("Zzz-PROBE", "a3")
    assert not t.blocked("someone-else", "a3")


async def test_success_does_not_count(monkeypatch, tmp_path):
    stub = StubSierra(204)
    ds = await setup(monkeypatch, tmp_path)
    with stubbed(stub):
        for _ in range(10):
            assert (await post_login(ds, "good-user", "pw")).status_code == 302
    assert stub.calls == 10


async def test_success_does_not_reset_the_cap(monkeypatch, tmp_path):
    ds = await setup(monkeypatch, tmp_path)
    ok, bad = StubSierra(204), StubSierra(400, BAD)
    with stubbed(bad):
        for _ in range(4):
            await post_login(ds, "mixed", "bad")
    with stubbed(ok):
        assert (await post_login(ds, "mixed", "pw")).status_code == 302
    with stubbed(bad):
        assert (await post_login(ds, "mixed", "bad")).status_code == 401  # 5th
        assert (await post_login(ds, "mixed", "bad")).status_code == 429


async def test_missing_credentials_and_local_mismatch_count(monkeypatch, tmp_path):
    stub = StubSierra(400, BAD)
    ds = await setup(monkeypatch, tmp_path)
    with stubbed(stub):
        for _ in range(3):
            assert (await post_login(ds, "x", "")).status_code == 400
        for _ in range(2):
            await post_login(ds, "x", "bad")
        assert (await post_login(ds, "x", "bad")).status_code == 429


async def test_disabled_account_counts(monkeypatch, tmp_path):
    stub = StubSierra(204)
    ds = await setup(monkeypatch, tmp_path)
    with stubbed(stub):
        await post_login(ds, "off", "pw")
    db = auth_db_for(tmp_path)
    db.set_user_active(db.get_user("off")["id"], False)
    with stubbed(stub):
        for _ in range(5):
            assert (await post_login(ds, "off", "pw")).status_code == 403
        assert (await post_login(ds, "off", "pw")).status_code == 429
