"""WordPress REST API exposure attacks — HIGH severity.

Tests for unprotected REST API endpoints that expose sensitive data
to unauthenticated users. Checks namespace enumeration, user listing,
draft post access, settings exposure, application passwords, and media.
"""

import json
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class RestApiExposureAttack(Attack):
    """Test for unprotected WordPress REST API endpoints exposing data."""

    name = "wordpress.rest_api_exposure"
    category = "wordpress"
    severity = Severity.HIGH
    description = "Unprotected REST API endpoints exposing sensitive data to unauthenticated users"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results = []

        results.append(await self._test_namespace_enumeration(client))
        results.append(await self._test_users_unauthenticated(client))
        results.append(await self._test_posts_private(client))
        results.append(await self._test_settings_exposure(client))
        results.append(await self._test_application_passwords(client))
        results.append(await self._test_media_unauthenticated(client))

        return results

    async def _test_namespace_enumeration(self, client) -> AttackResult:
        """GET /wp-json/ — enumerate all registered namespaces and routes."""
        start = time.monotonic()
        try:
            status, body, headers = await client.rest_get("/", authenticated=False)
            duration = (time.monotonic() - start) * 1000

            namespaces = []
            routes = []
            try:
                data = json.loads(body)
                namespaces = data.get("namespaces", [])
                routes = list(data.get("routes", {}).keys())
            except (json.JSONDecodeError, AttributeError):
                pass

            if status == 200 and namespaces:
                return self._make_result(
                    variant="namespace_enumeration",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"Found {len(namespaces)} namespaces, {len(routes)} routes",
                    details=(
                        f"REST API index at /wp-json/ returned HTTP {status}. "
                        f"Namespaces: {', '.join(namespaces[:10])}. "
                        f"Total routes: {len(routes)}. "
                        f"This reveals installed plugins and available attack surface."
                    ),
                    request={"method": "GET", "path": "/wp-json/"},
                    response={"status": status, "namespaces": namespaces[:10], "route_count": len(routes)},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="namespace_enumeration",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, REST index not exposed or empty",
                details=f"REST API index returned HTTP {status} with no namespace data.",
                request={"method": "GET", "path": "/wp-json/"},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="namespace_enumeration",
                status=Status.ERROR,
                details=f"Error enumerating namespaces: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_users_unauthenticated(self, client) -> AttackResult:
        """GET /wp-json/wp/v2/users without auth — check for user data leakage."""
        start = time.monotonic()
        try:
            status, body, headers = await client.rest_get(
                "/wp/v2/users", authenticated=False
            )
            duration = (time.monotonic() - start) * 1000

            users = []
            try:
                data = json.loads(body)
                if isinstance(data, list):
                    users = data
            except (json.JSONDecodeError, AttributeError):
                pass

            if status == 200 and users:
                usernames = [u.get("slug", u.get("name", "?")) for u in users[:10]]
                has_emails = any("email" in u for u in users)
                sev = Severity.HIGH if has_emails else Severity.HIGH

                return self._make_result(
                    variant="users_unauthenticated",
                    status=Status.VULNERABLE,
                    severity=sev,
                    evidence=f"Unauthenticated access returned {len(users)} users: {usernames}",
                    details=(
                        f"GET /wp-json/wp/v2/users without authentication returned "
                        f"{len(users)} user records. Usernames: {', '.join(usernames)}. "
                        f"Email exposed: {has_emails}. "
                        f"This enables targeted brute-force and social engineering attacks."
                    ),
                    request={"method": "GET", "path": "/wp-json/wp/v2/users", "authenticated": False},
                    response={"status": status, "user_count": len(users), "usernames": usernames},
                    duration_ms=duration,
                )

            if status in (401, 403):
                return self._make_result(
                    variant="users_unauthenticated",
                    status=Status.DEFENDED,
                    evidence=f"HTTP {status} — authentication required",
                    details=f"User endpoint correctly requires authentication (HTTP {status}).",
                    request={"method": "GET", "path": "/wp-json/wp/v2/users", "authenticated": False},
                    response={"status": status},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="users_unauthenticated",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no user data returned",
                details=f"User endpoint returned HTTP {status} with no user data.",
                request={"method": "GET", "path": "/wp-json/wp/v2/users", "authenticated": False},
                response={"status": status, "body": body[:300]},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="users_unauthenticated",
                status=Status.ERROR,
                details=f"Error testing users endpoint: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_posts_private(self, client) -> AttackResult:
        """GET /wp-json/wp/v2/posts?status=draft without auth — check for draft leakage."""
        start = time.monotonic()
        try:
            status, body, headers = await client.rest_get(
                "/wp/v2/posts", params={"status": "draft"}, authenticated=False
            )
            duration = (time.monotonic() - start) * 1000

            posts = []
            try:
                data = json.loads(body)
                if isinstance(data, list):
                    posts = data
            except (json.JSONDecodeError, AttributeError):
                pass

            if status == 200 and posts:
                titles = [
                    p.get("title", {}).get("rendered", "?") if isinstance(p.get("title"), dict)
                    else str(p.get("title", "?"))
                    for p in posts[:5]
                ]
                return self._make_result(
                    variant="posts_private",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Unauthenticated access returned {len(posts)} draft posts",
                    details=(
                        f"GET /wp-json/wp/v2/posts?status=draft without auth returned "
                        f"{len(posts)} draft posts. Titles: {titles}. "
                        f"Draft content should never be accessible without authentication."
                    ),
                    request={"method": "GET", "path": "/wp-json/wp/v2/posts?status=draft", "authenticated": False},
                    response={"status": status, "post_count": len(posts), "titles": titles},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="posts_private",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no draft posts returned",
                details=f"Draft posts endpoint returned HTTP {status} — drafts not exposed.",
                request={"method": "GET", "path": "/wp-json/wp/v2/posts?status=draft", "authenticated": False},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="posts_private",
                status=Status.ERROR,
                details=f"Error testing draft posts: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_settings_exposure(self, client) -> AttackResult:
        """GET /wp-json/wp/v2/settings without auth — check for site settings exposure."""
        start = time.monotonic()
        try:
            status, body, headers = await client.rest_get(
                "/wp/v2/settings", authenticated=False
            )
            duration = (time.monotonic() - start) * 1000

            settings = {}
            try:
                data = json.loads(body)
                if isinstance(data, dict) and not data.get("code"):
                    settings = data
            except (json.JSONDecodeError, AttributeError):
                pass

            if status == 200 and settings:
                keys = list(settings.keys())[:10]
                return self._make_result(
                    variant="settings_exposure",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Settings endpoint returned {len(settings)} settings: {keys}",
                    details=(
                        f"GET /wp-json/wp/v2/settings without auth returned "
                        f"{len(settings)} site settings. Keys: {', '.join(keys)}. "
                        f"Settings may contain admin email, site title, and other sensitive config."
                    ),
                    request={"method": "GET", "path": "/wp-json/wp/v2/settings", "authenticated": False},
                    response={"status": status, "setting_keys": keys},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="settings_exposure",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, settings not exposed",
                details=f"Settings endpoint returned HTTP {status} — properly restricted.",
                request={"method": "GET", "path": "/wp-json/wp/v2/settings", "authenticated": False},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="settings_exposure",
                status=Status.ERROR,
                details=f"Error testing settings: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_application_passwords(self, client) -> AttackResult:
        """GET /wp-json/wp/v2/users/me/application-passwords without auth."""
        start = time.monotonic()
        try:
            status, body, headers = await client.rest_get(
                "/wp/v2/users/me/application-passwords", authenticated=False
            )
            duration = (time.monotonic() - start) * 1000

            passwords = []
            try:
                data = json.loads(body)
                if isinstance(data, list):
                    passwords = data
            except (json.JSONDecodeError, AttributeError):
                pass

            if status == 200 and passwords:
                return self._make_result(
                    variant="application_passwords",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f"Application passwords endpoint returned {len(passwords)} entries",
                    details=(
                        f"GET /wp-json/wp/v2/users/me/application-passwords without auth "
                        f"returned {len(passwords)} application password entries. "
                        f"This is a critical authentication bypass."
                    ),
                    request={"method": "GET", "path": "/wp-json/wp/v2/users/me/application-passwords", "authenticated": False},
                    response={"status": status, "count": len(passwords)},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="application_passwords",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, application passwords not exposed",
                details=f"Application passwords endpoint returned HTTP {status} — properly restricted.",
                request={"method": "GET", "path": "/wp-json/wp/v2/users/me/application-passwords", "authenticated": False},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="application_passwords",
                status=Status.ERROR,
                details=f"Error testing application passwords: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_media_unauthenticated(self, client) -> AttackResult:
        """GET /wp-json/wp/v2/media without auth — check for private media exposure."""
        start = time.monotonic()
        try:
            status, body, headers = await client.rest_get(
                "/wp/v2/media", authenticated=False
            )
            duration = (time.monotonic() - start) * 1000

            media_items = []
            try:
                data = json.loads(body)
                if isinstance(data, list):
                    media_items = data
            except (json.JSONDecodeError, AttributeError):
                pass

            if status == 200 and media_items:
                # Check if any items have non-public status
                private_items = [
                    m for m in media_items
                    if m.get("status") not in ("publish", "inherit")
                ]
                urls = [
                    m.get("source_url", m.get("link", "?"))
                    for m in media_items[:5]
                ]

                if private_items:
                    return self._make_result(
                        variant="media_unauthenticated",
                        status=Status.VULNERABLE,
                        severity=Severity.HIGH,
                        evidence=f"Found {len(private_items)} private media items among {len(media_items)} total",
                        details=(
                            f"GET /wp-json/wp/v2/media without auth returned "
                            f"{len(media_items)} media items including {len(private_items)} "
                            f"non-public items. Private media files are accessible."
                        ),
                        request={"method": "GET", "path": "/wp-json/wp/v2/media", "authenticated": False},
                        response={"status": status, "total": len(media_items), "private": len(private_items)},
                        duration_ms=duration,
                    )

                # Public media listed — informational but not a vulnerability
                return self._make_result(
                    variant="media_unauthenticated",
                    status=Status.DEFENDED,
                    evidence=f"HTTP {status}, {len(media_items)} public media items (no private exposure)",
                    details=(
                        f"Media endpoint returned {len(media_items)} items, all public. "
                        f"No private media exposed. Sample URLs: {urls}"
                    ),
                    request={"method": "GET", "path": "/wp-json/wp/v2/media", "authenticated": False},
                    response={"status": status, "count": len(media_items)},
                    duration_ms=duration,
                )

            if status in (401, 403):
                return self._make_result(
                    variant="media_unauthenticated",
                    status=Status.DEFENDED,
                    evidence=f"HTTP {status} — authentication required",
                    details=f"Media endpoint correctly requires authentication (HTTP {status}).",
                    request={"method": "GET", "path": "/wp-json/wp/v2/media", "authenticated": False},
                    response={"status": status},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="media_unauthenticated",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no media data returned",
                details=f"Media endpoint returned HTTP {status} with no media items.",
                request={"method": "GET", "path": "/wp-json/wp/v2/media", "authenticated": False},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="media_unauthenticated",
                status=Status.ERROR,
                details=f"Error testing media endpoint: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
