"""
Login and logout route handlers.
"""

import os
import time

from datasette import Response

from . import COOKIE_NAME, COOKIE_MAX_AGE, get_auth_db, get_sierra_client


async def login(datasette, request):
    """Handle login form display and submission."""
    if request.method == "GET":
        return Response.html(
            await datasette.render_template(
                "sierra_auth_login.html",
                {"error": None},
                request=request,
            )
        )

    # POST - handle login
    form = await request.post_vars()
    sierra_login = form.get("username", "").strip()
    password = form.get("password", "")

    auth_db = get_auth_db(datasette)

    if not sierra_login or not password:
        auth_db.log_event(sierra_login or "(empty)", "login_failure", "Missing credentials")
        return Response.html(
            await datasette.render_template(
                "sierra_auth_login.html",
                {"error": "Username and password are required"},
                request=request,
            ),
            status=400,
        )

    # First, check for local password (built-in admin or other local accounts)
    authenticated = False
    if auth_db.check_local_password(sierra_login, password):
        authenticated = True
    else:
        # Try Sierra API
        sierra = get_sierra_client(datasette)
        if not sierra:
            return Response.html(
                await datasette.render_template(
                    "sierra_auth_login.html",
                    {"error": "Sierra API not configured"},
                    request=request,
                ),
                status=500,
            )

        try:
            response = await sierra.async_request(
                "POST",
                "users/validate",
                json={"username": sierra_login, "password": password},
            )
            if response.status_code == 204:
                authenticated = True
        except Exception as e:
            auth_db.log_event(sierra_login, "login_failure", f"Sierra API error: {e}")
            return Response.html(
                await datasette.render_template(
                    "sierra_auth_login.html",
                    {"error": "Authentication service unavailable"},
                    request=request,
                ),
                status=503,
            )

    if not authenticated:
        auth_db.log_event(sierra_login, "login_failure", "Invalid credentials")
        return Response.html(
            await datasette.render_template(
                "sierra_auth_login.html",
                {"error": "Invalid username or password"},
                request=request,
            ),
            status=401,
        )

    # Successful authentication - get or create local user
    user = auth_db.get_user(sierra_login)
    if not user:
        user = auth_db.create_user(sierra_login)

    if not user["is_active"]:
        auth_db.log_event(sierra_login, "login_failure", "Account disabled")
        return Response.html(
            await datasette.render_template(
                "sierra_auth_login.html",
                {"error": "Your account has been disabled"},
                request=request,
            ),
            status=403,
        )

    # Update last login and log success
    auth_db.update_last_login(user["id"])
    auth_db.log_event(sierra_login, "login_success")

    # Create signed session cookie
    redirect_url = os.environ.get("SIERRA_AUTH_LOGIN_REDIRECT", "/")
    response = Response.redirect(redirect_url)
    response.set_cookie(
        COOKIE_NAME,
        datasette.sign({"id": user["sierra_login"], "ts": time.time()}, "sierra-auth"),
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


async def logout(datasette, request):
    """Handle logout - clear the session cookie."""
    response = Response.redirect("/")
    response.set_cookie(COOKIE_NAME, "", expires=0)

    # Log the logout if we can identify the user
    cookie = request.cookies.get(COOKIE_NAME)
    if cookie:
        try:
            payload = datasette.unsign(cookie, "sierra-auth")
            sierra_login = payload.get("id")
            if sierra_login:
                auth_db = get_auth_db(datasette)
                auth_db.log_event(sierra_login, "logout")
        except Exception:
            pass

    return response


# Admin views

def require_permission(permission):
    """Decorator to require a specific permission."""
    def decorator(func):
        async def wrapper(datasette, request):
            actor = request.actor
            if not actor:
                return Response.redirect("/-/sierra-auth/login")

            # Check permission
            if "admin" not in actor.get("roles", []):
                if permission not in actor.get("_permissions", []):
                    return Response.html(
                        await datasette.render_template(
                            "sierra_auth_error.html",
                            {"error": "You do not have permission to access this page."},
                            request=request,
                        ),
                        status=403,
                    )
            return await func(datasette, request)
        return wrapper
    return decorator


async def admin_users(datasette, request):
    """Admin page to list and manage users."""
    actor = request.actor
    if not actor:
        return Response.redirect("/-/sierra-auth/login")

    # Check permission
    if "admin" not in actor.get("roles", []) and "manage-users" not in actor.get("_permissions", []):
        return Response.html(
            await datasette.render_template(
                "sierra_auth_error.html",
                {"error": "You do not have permission to access this page."},
                request=request,
            ),
            status=403,
        )

    auth_db = get_auth_db(datasette)
    users = auth_db.list_users()
    roles = auth_db.list_roles()

    return Response.html(
        await datasette.render_template(
            "sierra_auth_admin_users.html",
            {"users": users, "roles": roles},
            request=request,
        )
    )


async def admin_user_edit(datasette, request):
    """Edit a specific user's roles."""
    actor = request.actor
    if not actor:
        return Response.redirect("/-/sierra-auth/login")

    if "admin" not in actor.get("roles", []) and "manage-users" not in actor.get("_permissions", []):
        return Response.html(
            await datasette.render_template(
                "sierra_auth_error.html",
                {"error": "You do not have permission to access this page."},
                request=request,
            ),
            status=403,
        )

    auth_db = get_auth_db(datasette)

    # Get user_id from URL
    user_id = int(request.url_vars["user_id"])
    user = auth_db.get_user_by_id(user_id)

    if not user:
        return Response.html(
            await datasette.render_template(
                "sierra_auth_error.html",
                {"error": "User not found."},
                request=request,
            ),
            status=404,
        )

    roles = auth_db.list_roles()
    message = None

    if request.method == "POST":
        # In Datasette 1.0, post_body gives us access to raw form data
        from urllib.parse import parse_qs
        body = await request.post_body()
        form_data = parse_qs(body.decode("utf-8"))

        # parse_qs returns lists for all values
        selected_roles = set(form_data.get("roles", []))
        current_roles = set(user["roles"])

        # Add new roles
        for role in selected_roles - current_roles:
            auth_db.assign_role(user_id, role, actor.get("id"))
            auth_db.log_event(
                user["sierra_login"],
                "role_granted",
                f"Role '{role}' granted by {actor['id']}"
            )

        # Remove unselected roles
        for role in current_roles - selected_roles:
            auth_db.remove_role(user_id, role)
            auth_db.log_event(
                user["sierra_login"],
                "role_revoked",
                f"Role '{role}' revoked by {actor['id']}"
            )

        # Handle active status
        is_active = form_data.get("is_active", ["0"])[0] == "1"
        if is_active != bool(user["is_active"]):
            auth_db.set_user_active(user_id, is_active)
            status = "activated" if is_active else "deactivated"
            auth_db.log_event(
                user["sierra_login"],
                f"user_{status}",
                f"By {actor['id']}"
            )

        # Refresh user data
        user = auth_db.get_user_by_id(user_id)
        message = "User updated successfully."

    return Response.html(
        await datasette.render_template(
            "sierra_auth_admin_user_edit.html",
            {"user": user, "roles": roles, "message": message},
            request=request,
        )
    )
