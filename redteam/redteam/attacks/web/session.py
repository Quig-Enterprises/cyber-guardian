"""Session cookie security tests.

Examines the Set-Cookie header from the login endpoint to verify that
the eqmon_session cookie has proper security attributes:
- HttpOnly: prevents JavaScript access (XSS cookie theft)
- Secure: cookie only sent over HTTPS
- SameSite: prevents cross-site request attachment

These tests authenticate by calling the login endpoint directly and
inspecting the raw Set-Cookie header in the response.
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class SessionAttack(Attack):
    """Test session cookie security attributes."""

    name = "web.session"
    category = "web"
    severity = Severity.MEDIUM
    description = "Session cookie security flag verification"

    async def execute(self, client) -> list[AttackResult]:
        """Login and examine the Set-Cookie header for security flags."""
        results = []

        # Perform a fresh login to capture the Set-Cookie header
        start = time.monotonic()
        try:
            status_code, body, headers = await client.post(
                "/api/auth/login.php",
                json_body={
                    "email": "redteam-sysadmin@test.com",
                    "password": "RedTeam$ysAdmin2026!",
                },
            )
        except Exception as e:
            logger.error(f"Failed to login for session tests: {e}")
            for variant in ["httponly_flag", "secure_flag", "samesite_attribute"]:
                results.append(self._make_result(
                    variant=variant, status=Status.ERROR, details=str(e),
                    duration_ms=(time.monotonic() - start) * 1000,
                ))
            return results

        login_duration = (time.monotonic() - start) * 1000

        # Extract the Set-Cookie header
        set_cookie = headers.get("Set-Cookie", "")
        set_cookie_lower = set_cookie.lower()

        logger.debug(f"Set-Cookie header: {set_cookie}")

        # Check HttpOnly flag
        results.append(self._check_httponly(set_cookie, set_cookie_lower, login_duration))
        results.append(self._check_secure(set_cookie, set_cookie_lower, login_duration))
        results.append(self._check_samesite(set_cookie, set_cookie_lower, login_duration))

        return results

    def _check_httponly(self, set_cookie: str, set_cookie_lower: str, duration: float) -> AttackResult:
        """Check if HttpOnly flag is set on the session cookie."""
        if "httponly" in set_cookie_lower:
            return self._make_result(
                variant="httponly_flag",
                status=Status.DEFENDED,
                evidence=f"HttpOnly flag present in Set-Cookie",
                details="Session cookie is not accessible via JavaScript (XSS cookie theft mitigated)",
                request={"checked": "HttpOnly flag"},
                response={"Set-Cookie": set_cookie[:200]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="httponly_flag",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"HttpOnly flag MISSING from Set-Cookie: {set_cookie[:200]}",
                details="Session cookie accessible via document.cookie - XSS can steal sessions",
                request={"checked": "HttpOnly flag"},
                response={"Set-Cookie": set_cookie[:200]},
                duration_ms=duration,
            )

    def _check_secure(self, set_cookie: str, set_cookie_lower: str, duration: float) -> AttackResult:
        """Check if Secure flag is set on the session cookie."""
        if "secure" in set_cookie_lower:
            return self._make_result(
                variant="secure_flag",
                status=Status.DEFENDED,
                evidence="Secure flag present in Set-Cookie",
                details="Session cookie only sent over HTTPS connections",
                request={"checked": "Secure flag"},
                response={"Set-Cookie": set_cookie[:200]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="secure_flag",
                status=Status.VULNERABLE,
                severity=Severity.MEDIUM,
                evidence=f"Secure flag MISSING from Set-Cookie: {set_cookie[:200]}",
                details="Session cookie can be sent over plain HTTP - network sniffing possible",
                request={"checked": "Secure flag"},
                response={"Set-Cookie": set_cookie[:200]},
                duration_ms=duration,
            )

    def _check_samesite(self, set_cookie: str, set_cookie_lower: str, duration: float) -> AttackResult:
        """Check if SameSite attribute is set on the session cookie."""
        if "samesite=strict" in set_cookie_lower:
            return self._make_result(
                variant="samesite_attribute",
                status=Status.DEFENDED,
                evidence="SameSite=Strict present in Set-Cookie",
                details="Cookie never sent in cross-site requests - strong CSRF protection",
                request={"checked": "SameSite attribute"},
                response={"Set-Cookie": set_cookie[:200]},
                duration_ms=duration,
            )
        elif "samesite=lax" in set_cookie_lower:
            return self._make_result(
                variant="samesite_attribute",
                status=Status.DEFENDED,
                evidence="SameSite=Lax present in Set-Cookie",
                details="Cookie only sent on top-level navigations - basic CSRF protection",
                request={"checked": "SameSite attribute"},
                response={"Set-Cookie": set_cookie[:200]},
                duration_ms=duration,
            )
        elif "samesite=none" in set_cookie_lower:
            return self._make_result(
                variant="samesite_attribute",
                status=Status.VULNERABLE,
                severity=Severity.MEDIUM,
                evidence="SameSite=None - cookie sent on all cross-site requests",
                details="No SameSite protection - cookie attached to all cross-origin requests",
                request={"checked": "SameSite attribute"},
                response={"Set-Cookie": set_cookie[:200]},
                duration_ms=duration,
            )
        else:
            return self._make_result(
                variant="samesite_attribute",
                status=Status.VULNERABLE,
                severity=Severity.MEDIUM,
                evidence=f"SameSite attribute MISSING from Set-Cookie: {set_cookie[:200]}",
                details="No SameSite attribute - browser defaults apply (Lax in modern browsers)",
                request={"checked": "SameSite attribute"},
                response={"Set-Cookie": set_cookie[:200]},
                duration_ms=duration,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by session tests."""
        pass
