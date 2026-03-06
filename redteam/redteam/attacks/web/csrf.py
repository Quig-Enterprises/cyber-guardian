"""CSRF (Cross-Site Request Forgery) attack variants.

Tests whether the API accepts cross-origin POST requests without CSRF
protection. If the server accepts POSTs with no Origin header, forged
Origin, or without any CSRF token, it is VULNERABLE.
"""

import time
import logging
import uuid

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class CSRFAttack(Attack):
    """Test CSRF protections on state-changing API endpoints."""

    name = "web.csrf"
    category = "web"
    severity = Severity.HIGH
    description = "Cross-site request forgery protection tests"

    async def execute(self, client) -> list[AttackResult]:
        """Run all CSRF variants."""
        results = []
        session_id = f"redteam-csrf-{uuid.uuid4().hex[:8]}"

        results.append(await self._test_no_origin(client, session_id))
        results.append(await self._test_forged_origin(client, session_id))
        results.append(await self._test_no_csrf_token(client, session_id))

        return results

    async def _test_no_origin(self, client, session_id: str) -> AttackResult:
        """POST chat message without any Origin header."""
        start = time.monotonic()
        try:
            # Send POST without Origin header (simulate cross-origin without browser)
            # Use raw post to control headers exactly
            status_code, body, headers = await client.post(
                "/api/ai_chat.php",
                json_body={
                    "action": "send_message",
                    "message": "CSRF test - no origin header",
                    "session_id": session_id,
                },
                headers={},  # Explicitly empty - no Origin
            )
            duration = (time.monotonic() - start) * 1000

            if status_code == 200:
                return self._make_result(
                    variant="no_origin_header",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Server accepted POST without Origin header (HTTP {status_code})",
                    details="API accepts requests without Origin header - susceptible to CSRF",
                    request={"headers": "no Origin", "session_id": session_id},
                    response={"status": status_code, "body": body[:300]},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="no_origin_header",
                    status=Status.DEFENDED,
                    evidence=f"Server rejected POST without Origin header (HTTP {status_code})",
                    details="API requires valid Origin header",
                    request={"headers": "no Origin"},
                    response={"status": status_code, "body": body[:300]},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="no_origin_header",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_forged_origin(self, client, session_id: str) -> AttackResult:
        """POST with Origin header set to an evil domain."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.post(
                "/api/ai_bearing_notes.php",
                json_body={
                    "action": "add_note",
                    "note": "CSRF test note - forged origin",
                    "bearing_id": "redteam-csrf-test",
                },
                headers={
                    "Origin": "https://evil.com",
                    "Referer": "https://evil.com/attack-page",
                },
            )
            duration = (time.monotonic() - start) * 1000

            if status_code == 200:
                return self._make_result(
                    variant="forged_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Server accepted POST with Origin: evil.com (HTTP {status_code})",
                    details="API accepts requests from arbitrary origins - CSRF possible",
                    request={"Origin": "https://evil.com", "Referer": "https://evil.com/attack-page"},
                    response={"status": status_code, "body": body[:300]},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="forged_origin",
                    status=Status.DEFENDED,
                    evidence=f"Server rejected forged Origin (HTTP {status_code})",
                    details="API validates Origin header against whitelist",
                    request={"Origin": "https://evil.com"},
                    response={"status": status_code, "body": body[:300]},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="forged_origin",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_no_csrf_token(self, client, session_id: str) -> AttackResult:
        """Check if any CSRF token mechanism is present."""
        start = time.monotonic()
        try:
            # First, GET the chat page to see if a CSRF token is issued
            get_status, get_body, get_headers = await client.get("/api/ai_chat.php",
                params={"action": "get_messages", "session_id": session_id})

            # Check response for common CSRF token patterns
            has_csrf_token = any(
                token_name in get_body.lower() or token_name in str(get_headers).lower()
                for token_name in ["csrf", "xsrf", "_token", "x-csrf", "x-xsrf"]
            )

            # Also check if POST works without any token
            post_status, post_body, post_headers = await client.post(
                "/api/ai_chat.php",
                json_body={
                    "action": "send_message",
                    "message": "CSRF token test",
                    "session_id": session_id,
                },
            )
            duration = (time.monotonic() - start) * 1000

            if not has_csrf_token and post_status == 200:
                return self._make_result(
                    variant="no_csrf_token",
                    status=Status.VULNERABLE,
                    severity=Severity.MEDIUM,
                    evidence="No CSRF token mechanism detected; POST accepted without token",
                    details="API relies solely on session cookie for authentication with no CSRF protection",
                    request={"checked_headers": True, "checked_body": True},
                    response={"has_token": False, "post_status": post_status},
                    duration_ms=duration,
                )
            elif has_csrf_token:
                return self._make_result(
                    variant="no_csrf_token",
                    status=Status.DEFENDED,
                    evidence="CSRF token mechanism detected in response",
                    details="API implements CSRF token protection",
                    request={"checked_headers": True, "checked_body": True},
                    response={"has_token": True},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="no_csrf_token",
                    status=Status.PARTIAL,
                    severity=Severity.MEDIUM,
                    evidence=f"No CSRF token found but POST returned {post_status}",
                    details="CSRF token not detected but POST may have been rejected for other reasons",
                    request={"checked_headers": True},
                    response={"has_token": False, "post_status": post_status},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="no_csrf_token",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """Clean up CSRF test artifacts."""
        pass
