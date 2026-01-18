"""Tests for views.py - login and logout flows."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import tempfile
from pathlib import Path

from datasette.app import Datasette


@pytest.fixture
def temp_db_path():
    """Create a temporary database path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def mock_sierra_client():
    """Create a mock Sierra API client."""
    client = MagicMock()
    client.async_request = AsyncMock()
    return client


def extract_csrftoken(response):
    """Extract CSRF token from response cookies."""
    for cookie in response.cookies.jar:
        if cookie.name == "ds_csrftoken":
            return cookie.value
    return None


@pytest.mark.asyncio
async def test_login_page_renders(temp_db_path):
    """GET /login should render the login form."""
    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}):
        datasette = Datasette(memory=True)
        response = await datasette.client.get("/-/sierra-auth/login")

    assert response.status_code == 200
    assert "Log in" in response.text
    assert "username" in response.text
    assert "password" in response.text


@pytest.mark.asyncio
async def test_login_requires_credentials(temp_db_path):
    """POST /login without credentials should show error."""
    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}):
        datasette = Datasette(memory=True)

        # Get CSRF token first
        login_page = await datasette.client.get("/-/sierra-auth/login")
        csrftoken = extract_csrftoken(login_page)

        response = await datasette.client.post(
            "/-/sierra-auth/login",
            data={"username": "", "password": "", "csrftoken": csrftoken},
        )

    assert response.status_code == 400
    assert "required" in response.text.lower()


@pytest.mark.asyncio
async def test_login_without_sierra_config_shows_error(temp_db_path):
    """POST /login without Sierra API configured should show error."""
    with patch.dict("os.environ", {
        "SIERRA_AUTH_DB_PATH": temp_db_path,
    }, clear=True):
        datasette = Datasette(memory=True)
        # Ensure no Sierra client
        datasette._sierra_client = None

        login_page = await datasette.client.get("/-/sierra-auth/login")
        csrftoken = extract_csrftoken(login_page)

        response = await datasette.client.post(
            "/-/sierra-auth/login",
            data={
                "username": "testuser",
                "password": "testpass",
                "csrftoken": csrftoken,
            },
        )

    assert response.status_code == 500
    assert "not configured" in response.text.lower()


@pytest.mark.asyncio
async def test_login_with_invalid_credentials(temp_db_path, mock_sierra_client):
    """POST /login with invalid Sierra credentials should show error."""
    # Mock Sierra returning 401
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_sierra_client.async_request.return_value = mock_response

    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}, clear=True):
        with patch("datasette_sierra_ils_auth.views.get_sierra_client", return_value=mock_sierra_client):
            datasette = Datasette(memory=True)

            login_page = await datasette.client.get("/-/sierra-auth/login")
            csrftoken = extract_csrftoken(login_page)

            response = await datasette.client.post(
                "/-/sierra-auth/login",
                data={
                    "username": "baduser",
                    "password": "badpass",
                    "csrftoken": csrftoken,
                },
            )

    assert response.status_code == 401
    assert "invalid" in response.text.lower()


@pytest.mark.asyncio
async def test_login_success_sets_cookie(temp_db_path, mock_sierra_client):
    """POST /login with valid credentials should set session cookie."""
    # Mock Sierra returning 204 (success)
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_sierra_client.async_request.return_value = mock_response

    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}, clear=True):
        with patch("datasette_sierra_ils_auth.views.get_sierra_client", return_value=mock_sierra_client):
            datasette = Datasette(memory=True)

            login_page = await datasette.client.get("/-/sierra-auth/login")
            csrftoken = extract_csrftoken(login_page)

            response = await datasette.client.post(
                "/-/sierra-auth/login",
                data={
                    "username": "gooduser",
                    "password": "goodpass",
                    "csrftoken": csrftoken,
                },
                follow_redirects=False,
            )

    assert response.status_code == 302  # Redirect after login
    # Check cookie was set
    cookie_set = any(c.name == "ds_sierra_auth" for c in response.cookies.jar)
    assert cookie_set


@pytest.mark.asyncio
async def test_login_creates_user_on_first_login(temp_db_path, mock_sierra_client):
    """First successful login should create user in local DB."""
    mock_response = MagicMock()
    mock_response.status_code = 204
    mock_sierra_client.async_request.return_value = mock_response

    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}, clear=True):
        with patch("datasette_sierra_ils_auth.views.get_sierra_client", return_value=mock_sierra_client):
            datasette = Datasette(memory=True)

            login_page = await datasette.client.get("/-/sierra-auth/login")
            csrftoken = extract_csrftoken(login_page)

            # Login
            await datasette.client.post(
                "/-/sierra-auth/login",
                data={
                    "username": "newuser",
                    "password": "pass",
                    "csrftoken": csrftoken,
                },
                follow_redirects=False,
            )

            # Check user was created
            from datasette_sierra_ils_auth.auth_db import AuthDB
            auth_db = AuthDB(Path(temp_db_path))
            user = auth_db.get_user("newuser")

    assert user is not None
    assert user["sierra_login"] == "newuser"
    assert "viewer" in user["roles"]


@pytest.mark.asyncio
async def test_logout_redirects(temp_db_path):
    """Logout should redirect to home."""
    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}, clear=True):
        datasette = Datasette(memory=True)

        response = await datasette.client.get(
            "/-/sierra-auth/logout",
            follow_redirects=False,
        )

    assert response.status_code == 302  # Redirect
    assert response.headers.get("location") == "/"


# Admin view tests

@pytest.mark.asyncio
async def test_admin_users_requires_login(temp_db_path):
    """Admin users page should redirect to login if not authenticated."""
    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}, clear=True):
        datasette = Datasette(memory=True)

        response = await datasette.client.get(
            "/-/sierra-auth/admin/users",
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert "login" in response.headers.get("location", "")


@pytest.mark.asyncio
async def test_admin_users_requires_permission(temp_db_path):
    """Admin users page should deny access without admin role."""
    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}, clear=True):
        datasette = Datasette(memory=True)

        # Create a non-admin actor
        with patch("datasette_sierra_ils_auth.views.get_auth_db") as mock_get_db:
            # Mock request with non-admin actor
            response = await datasette.client.get(
                "/-/sierra-auth/admin/users",
                cookies={"ds_actor": datasette.sign({"a": {"id": "user", "roles": ["viewer"], "_permissions": []}}, "actor")},
            )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_user_edit_requires_login(temp_db_path):
    """Admin user edit page should redirect to login if not authenticated."""
    with patch.dict("os.environ", {"SIERRA_AUTH_DB_PATH": temp_db_path}, clear=True):
        datasette = Datasette(memory=True)

        response = await datasette.client.get(
            "/-/sierra-auth/admin/users/1",
            follow_redirects=False,
        )

    assert response.status_code == 302
    assert "login" in response.headers.get("location", "")
