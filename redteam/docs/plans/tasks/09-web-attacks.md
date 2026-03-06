# Task 09: Web Attack Modules

Tests for web-layer vulnerabilities: XSS, CSRF, CORS misconfigurations, and session cookie security. These check what happens when malicious content is stored/reflected and whether browser-side protections are enforced.

## Files

- `redteam/attacks/web/xss.py` - Stored/reflected XSS attack variants
- `redteam/attacks/web/csrf.py` - Cross-site request forgery tests
- `redteam/attacks/web/cors.py` - CORS misconfiguration tests
- `redteam/attacks/web/session.py` - Session cookie security tests
- `tests/test_web_attacks.py` - Unit tests

---

## Step 1: Write tests/test_web_attacks.py

Create `/opt/security-red-team/tests/test_web_attacks.py`:

```python
"""Tests for web attack modules: XSS, CSRF, CORS, Session."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from redteam.base import AttackResult, Severity, Status
from redteam.attacks.web.xss import XSSAttack
from redteam.attacks.web.csrf import CSRFAttack
from redteam.attacks.web.cors import CORSAttack
from redteam.attacks.web.session import SessionAttack


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_mock_client(**overrides):
    """Create a mock RedTeamClient with default behaviors."""
    client = MagicMock()
    client.post = AsyncMock(return_value=(200, '{"success": true}', {"Content-Type": "application/json"}))
    client.get = AsyncMock(return_value=(200, '{"messages": []}', {"Content-Type": "application/json"}))
    client.chat = AsyncMock()
    client.base_url = "http://localhost:8081/eqmon"
    client._cookies = {"eqmon_session": "test_jwt_token"}
    for k, v in overrides.items():
        setattr(client, k, v)
    return client


# ---------------------------------------------------------------------------
# XSSAttack
# ---------------------------------------------------------------------------

class TestXSSAttackMetadata:
    def test_name(self):
        attack = XSSAttack()
        assert attack.name == "web.xss"

    def test_category(self):
        attack = XSSAttack()
        assert attack.category == "web"

    def test_severity(self):
        attack = XSSAttack()
        assert attack.severity == Severity.HIGH

    def test_has_description(self):
        attack = XSSAttack()
        assert len(attack.description) > 0


class TestXSSAttackExecution:
    @pytest.mark.asyncio
    async def test_returns_list_of_results(self):
        client = make_mock_client()
        # Simulate messages endpoint returning escaped content
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        client.get = AsyncMock(return_value=(
            200,
            '{"messages": [{"content": "&lt;script&gt;alert(\'XSS\')&lt;/script&gt;"}]}',
            {}
        ))
        attack = XSSAttack()
        results = await attack.execute(client)
        assert isinstance(results, list)
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_detects_unescaped_script_tag(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        # Response contains unescaped payload - VULNERABLE
        client.get = AsyncMock(return_value=(
            200,
            '{"messages": [{"content": "<script>alert(\'XSS\')</script>"}]}',
            {}
        ))
        attack = XSSAttack()
        results = await attack.execute(client)
        script_results = [r for r in results if r.variant == "script_tag"]
        assert len(script_results) >= 1
        assert script_results[0].status == Status.VULNERABLE

    @pytest.mark.asyncio
    async def test_detects_escaped_script_tag(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        # Response has HTML-escaped payload - DEFENDED
        client.get = AsyncMock(return_value=(
            200,
            '{"messages": [{"content": "&lt;script&gt;alert(\'XSS\')&lt;/script&gt;"}]}',
            {}
        ))
        attack = XSSAttack()
        results = await attack.execute(client)
        script_results = [r for r in results if r.variant == "script_tag"]
        assert len(script_results) >= 1
        assert script_results[0].status == Status.DEFENDED

    @pytest.mark.asyncio
    async def test_has_six_variants(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        client.get = AsyncMock(return_value=(200, '{"messages": []}', {}))
        attack = XSSAttack()
        results = await attack.execute(client)
        assert len(results) == 6

    @pytest.mark.asyncio
    async def test_score_aggregation(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        client.get = AsyncMock(return_value=(200, '{"messages": []}', {}))
        attack = XSSAttack()
        results = await attack.execute(client)
        score = attack.score(results)
        assert score.total_variants == 6
        assert score.attack_name == "web.xss"


# ---------------------------------------------------------------------------
# CSRFAttack
# ---------------------------------------------------------------------------

class TestCSRFAttackMetadata:
    def test_name(self):
        attack = CSRFAttack()
        assert attack.name == "web.csrf"

    def test_category(self):
        attack = CSRFAttack()
        assert attack.category == "web"

    def test_severity(self):
        attack = CSRFAttack()
        assert attack.severity == Severity.HIGH


class TestCSRFAttackExecution:
    @pytest.mark.asyncio
    async def test_returns_list_of_results(self):
        client = make_mock_client()
        attack = CSRFAttack()
        results = await attack.execute(client)
        assert isinstance(results, list)
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_has_three_variants(self):
        client = make_mock_client()
        attack = CSRFAttack()
        results = await attack.execute(client)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_no_origin_header_variant(self):
        client = make_mock_client()
        # Server accepts POST without Origin - VULNERABLE
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        attack = CSRFAttack()
        results = await attack.execute(client)
        no_origin = [r for r in results if r.variant == "no_origin_header"]
        assert len(no_origin) == 1

    @pytest.mark.asyncio
    async def test_forged_origin_variant(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        attack = CSRFAttack()
        results = await attack.execute(client)
        forged = [r for r in results if r.variant == "forged_origin"]
        assert len(forged) == 1

    @pytest.mark.asyncio
    async def test_no_csrf_token_variant(self):
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '{"success": true}', {}))
        attack = CSRFAttack()
        results = await attack.execute(client)
        token = [r for r in results if r.variant == "no_csrf_token"]
        assert len(token) == 1


# ---------------------------------------------------------------------------
# CORSAttack
# ---------------------------------------------------------------------------

class TestCORSAttackMetadata:
    def test_name(self):
        attack = CORSAttack()
        assert attack.name == "web.cors"

    def test_category(self):
        attack = CORSAttack()
        assert attack.category == "web"

    def test_severity(self):
        attack = CORSAttack()
        assert attack.severity == Severity.HIGH


class TestCORSAttackExecution:
    @pytest.mark.asyncio
    async def test_returns_list_of_results(self):
        client = make_mock_client()
        attack = CORSAttack()
        results = await attack.execute(client)
        assert isinstance(results, list)
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_has_three_variants(self):
        client = make_mock_client()
        attack = CORSAttack()
        results = await attack.execute(client)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_detects_wildcard_acao_critical(self):
        """ACAO: * with credentials: true is CRITICAL."""
        client = make_mock_client()
        client.post = AsyncMock(return_value=(
            200, '',
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        ))
        attack = CORSAttack()
        results = await attack.execute(client)
        preflight = [r for r in results if r.variant == "preflight_evil_origin"]
        assert len(preflight) == 1
        assert preflight[0].status == Status.VULNERABLE
        assert preflight[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_acao_header_is_defended(self):
        """No ACAO header means CORS is not enabled - DEFENDED."""
        client = make_mock_client()
        client.post = AsyncMock(return_value=(200, '', {"Content-Type": "application/json"}))
        client.get = AsyncMock(return_value=(200, '', {"Content-Type": "application/json"}))
        attack = CORSAttack()
        results = await attack.execute(client)
        for r in results:
            if "Access-Control-Allow-Origin" not in str(r.evidence):
                assert r.status == Status.DEFENDED


# ---------------------------------------------------------------------------
# SessionAttack
# ---------------------------------------------------------------------------

class TestSessionAttackMetadata:
    def test_name(self):
        attack = SessionAttack()
        assert attack.name == "web.session"

    def test_category(self):
        attack = SessionAttack()
        assert attack.category == "web"

    def test_severity(self):
        attack = SessionAttack()
        assert attack.severity == Severity.MEDIUM


class TestSessionAttackExecution:
    @pytest.mark.asyncio
    async def test_returns_list_of_results(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        assert isinstance(results, list)
        assert all(isinstance(r, AttackResult) for r in results)

    @pytest.mark.asyncio
    async def test_has_three_variants(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_checks_httponly_flag(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        httponly = [r for r in results if r.variant == "httponly_flag"]
        assert len(httponly) == 1

    @pytest.mark.asyncio
    async def test_checks_secure_flag(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        secure = [r for r in results if r.variant == "secure_flag"]
        assert len(secure) == 1

    @pytest.mark.asyncio
    async def test_checks_samesite_attribute(self):
        client = make_mock_client()
        attack = SessionAttack()
        results = await attack.execute(client)
        samesite = [r for r in results if r.variant == "samesite_attribute"]
        assert len(samesite) == 1

    @pytest.mark.asyncio
    async def test_missing_httponly_is_vulnerable(self):
        """Set-Cookie without HttpOnly is VULNERABLE."""
        client = make_mock_client()
        # Login returns Set-Cookie without HttpOnly
        client.post = AsyncMock(return_value=(
            200, '{"success": true}',
            {"Set-Cookie": "eqmon_session=jwt_value; Path=/; Secure; SameSite=Strict"}
        ))
        attack = SessionAttack()
        results = await attack.execute(client)
        httponly = [r for r in results if r.variant == "httponly_flag"]
        assert len(httponly) == 1
        assert httponly[0].status == Status.VULNERABLE

    @pytest.mark.asyncio
    async def test_all_flags_present_is_defended(self):
        """Set-Cookie with all flags is DEFENDED."""
        client = make_mock_client()
        client.post = AsyncMock(return_value=(
            200, '{"success": true}',
            {"Set-Cookie": "eqmon_session=jwt_value; Path=/; HttpOnly; Secure; SameSite=Strict"}
        ))
        attack = SessionAttack()
        results = await attack.execute(client)
        for r in results:
            assert r.status == Status.DEFENDED
```

---

## Step 2: Run tests to verify failures

```bash
cd /opt/security-red-team
source venv/bin/activate
python -m pytest tests/test_web_attacks.py -v 2>&1 | head -60
```

Expected: All tests fail because the web attack modules do not yet exist.

---

## Step 3: Write redteam/attacks/web/xss.py

Create `/opt/security-red-team/redteam/attacks/web/xss.py`:

```python
"""Stored/reflected XSS attack variants.

Tests whether malicious HTML/JavaScript payloads injected through chat
messages and bearing notes are returned unsanitized. If the exact payload
appears unescaped in the GET response, it is VULNERABLE. If HTML entities
are escaped (e.g., &lt;script&gt;), it is DEFENDED.
"""

import json
import time
import logging
import uuid

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class XSSAttack(Attack):
    """Test stored XSS through chat messages and bearing notes."""

    name = "web.xss"
    category = "web"
    severity = Severity.HIGH
    description = "Stored/reflected XSS via chat messages and bearing notes"

    # Each variant: (variant_name, payload, description, injection_target)
    VARIANTS = [
        (
            "script_tag",
            "<script>alert('XSS')</script>",
            "Basic script tag injection in chat message",
            "chat",
        ),
        (
            "event_handler",
            "<img src=x onerror=alert('XSS')>",
            "Event handler injection in bearing note",
            "note",
        ),
        (
            "svg_onload",
            "<svg onload=alert('XSS')>",
            "SVG onload injection in chat message",
            "chat",
        ),
        (
            "markdown_javascript",
            "[Click me](javascript:alert('XSS'))",
            "Markdown link with javascript: URI",
            "chat",
        ),
        (
            "html_entity_bypass",
            "<scr&#x69;pt>alert('XSS')</script>",
            "HTML entity encoding bypass attempt",
            "chat",
        ),
        (
            "css_injection",
            '<div style="background:url(javascript:alert(\'XSS\'))">',
            "CSS injection via style attribute in bearing note",
            "note",
        ),
    ]

    async def execute(self, client) -> list[AttackResult]:
        """Run all XSS variants against chat and note endpoints."""
        results = []
        session_id = f"redteam-xss-{uuid.uuid4().hex[:8]}"

        for variant_name, payload, description, target in self.VARIANTS:
            start = time.monotonic()
            try:
                if target == "chat":
                    result = await self._test_chat_xss(
                        client, variant_name, payload, description, session_id
                    )
                else:
                    result = await self._test_note_xss(
                        client, variant_name, payload, description
                    )
                result.duration_ms = (time.monotonic() - start) * 1000
                results.append(result)
            except Exception as e:
                logger.error(f"Error running XSS variant {variant_name}: {e}")
                results.append(self._make_result(
                    variant=variant_name,
                    status=Status.ERROR,
                    details=str(e),
                    duration_ms=(time.monotonic() - start) * 1000,
                ))

        return results

    async def _test_chat_xss(
        self, client, variant: str, payload: str, description: str, session_id: str
    ) -> AttackResult:
        """Inject XSS payload via chat message, then GET and check response."""
        # POST the payload as a chat message
        status_code, body, headers = await client.post(
            "/api/ai_chat.php",
            json_body={
                "action": "send_message",
                "message": payload,
                "session_id": session_id,
            },
        )

        # GET the messages back to check if payload is stored unsanitized
        get_status, get_body, get_headers = await client.get(
            "/api/ai_chat.php",
            params={"action": "get_messages", "session_id": session_id},
        )

        return self._evaluate_xss(variant, payload, description, get_body,
                                   request={"payload": payload, "target": "chat", "session_id": session_id},
                                   response={"status": get_status, "body": get_body[:500]})

    async def _test_note_xss(
        self, client, variant: str, payload: str, description: str
    ) -> AttackResult:
        """Inject XSS payload via bearing note, then GET and check response."""
        # POST the payload as a bearing note
        status_code, body, headers = await client.post(
            "/api/ai_bearing_notes.php",
            json_body={
                "action": "add_note",
                "note": payload,
                "bearing_id": "redteam-xss-test",
            },
        )

        # GET the notes back
        get_status, get_body, get_headers = await client.get(
            "/api/ai_bearing_notes.php",
            params={"action": "get_notes", "bearing_id": "redteam-xss-test"},
        )

        return self._evaluate_xss(variant, payload, description, get_body,
                                   request={"payload": payload, "target": "note"},
                                   response={"status": get_status, "body": get_body[:500]})

    def _evaluate_xss(
        self, variant: str, payload: str, description: str,
        response_body: str, request: dict, response: dict
    ) -> AttackResult:
        """Check if the payload appears unescaped in the response."""
        # If the exact payload appears in the response body, it's unescaped
        if payload in response_body:
            return self._make_result(
                variant=variant,
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"Payload returned unescaped: {payload}",
                details=f"{description} - payload stored and reflected without sanitization",
                request=request,
                response=response,
            )

        # Check for common escaped forms (HTML entity encoding)
        escaped_checks = [
            payload.replace("<", "&lt;").replace(">", "&gt;"),
            payload.replace('"', "&quot;").replace("'", "&#x27;"),
        ]
        for escaped in escaped_checks:
            if escaped in response_body:
                return self._make_result(
                    variant=variant,
                    status=Status.DEFENDED,
                    evidence=f"Payload was HTML-escaped in response",
                    details=f"{description} - properly sanitized",
                    request=request,
                    response=response,
                )

        # Payload not found at all (maybe stripped entirely or endpoint not storing)
        return self._make_result(
            variant=variant,
            status=Status.DEFENDED,
            evidence="Payload not found in response (stripped or not stored)",
            details=f"{description} - payload not reflected",
            request=request,
            response=response,
        )

    async def cleanup(self, client) -> None:
        """Clean up test chat messages and notes."""
        try:
            await client.post("/api/ai_chat.php", json_body={
                "action": "delete_session",
                "session_id_prefix": "redteam-xss-",
            })
        except Exception:
            pass
```

---

## Step 4: Write redteam/attacks/web/csrf.py

Create `/opt/security-red-team/redteam/attacks/web/csrf.py`:

```python
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
```

---

## Step 5: Write redteam/attacks/web/cors.py

Create `/opt/security-red-team/redteam/attacks/web/cors.py`:

```python
"""CORS (Cross-Origin Resource Sharing) misconfiguration tests.

Tests whether the API returns overly permissive CORS headers that would
allow malicious sites to make authenticated cross-origin requests.

Evaluation:
- Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true -> CRITICAL
- Access-Control-Allow-Origin: * without credentials -> HIGH
- Origin echoed back with credentials allowed -> CRITICAL
- Restrictive or absent CORS headers -> DEFENDED
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class CORSAttack(Attack):
    """Test CORS configuration for overly permissive policies."""

    name = "web.cors"
    category = "web"
    severity = Severity.HIGH
    description = "CORS misconfiguration and credential exposure tests"

    async def execute(self, client) -> list[AttackResult]:
        """Run all CORS variants."""
        results = []

        results.append(await self._test_preflight_evil_origin(client))
        results.append(await self._test_get_with_evil_origin(client))
        results.append(await self._test_credentials_header(client))

        return results

    async def _test_preflight_evil_origin(self, client) -> AttackResult:
        """Send OPTIONS preflight from evil.com and check ACAO header."""
        start = time.monotonic()
        try:
            # Simulate preflight by sending POST with evil Origin
            # (OPTIONS is typically handled by the web server, so we test
            # via actual request with Origin header to see response headers)
            status_code, body, headers = await client.post(
                "/api/ai_chat.php",
                json_body={"action": "get_messages", "session_id": "redteam-cors-test"},
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type",
                },
            )
            duration = (time.monotonic() - start) * 1000

            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == "*" and acac == "true":
                return self._make_result(
                    variant="preflight_evil_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    details="Wildcard ACAO with credentials allowed - any site can make authenticated requests",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao, "ACAC": acac, "status": status_code},
                    duration_ms=duration,
                )
            elif acao == "https://evil.com":
                sev = Severity.CRITICAL if acac == "true" else Severity.HIGH
                return self._make_result(
                    variant="preflight_evil_origin",
                    status=Status.VULNERABLE,
                    severity=sev,
                    evidence=f"Server reflected evil Origin: ACAO={acao}, ACAC={acac}",
                    details="Origin reflection - server echoes back any Origin value",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao, "ACAC": acac},
                    duration_ms=duration,
                )
            elif acao == "*":
                return self._make_result(
                    variant="preflight_evil_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"ACAO: * (wildcard without credentials)",
                    details="Wildcard CORS allows any site to read responses (no credentials)",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao, "ACAC": acac or "not set"},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="preflight_evil_origin",
                    status=Status.DEFENDED,
                    evidence=f"ACAO: '{acao}' (not permissive)",
                    details="CORS properly configured - evil origin not allowed",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao or "not set", "ACAC": acac or "not set"},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="preflight_evil_origin",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_get_with_evil_origin(self, client) -> AttackResult:
        """GET with Origin: evil.com and check if credentials are allowed."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get(
                "/api/ai_chat.php",
                params={"action": "get_messages", "session_id": "redteam-cors-test"},
                headers={"Origin": "https://evil.com"},
            )
            duration = (time.monotonic() - start) * 1000

            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao in ("*", "https://evil.com") and acac == "true":
                return self._make_result(
                    variant="get_evil_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.CRITICAL,
                    evidence=f"GET responds with ACAO={acao}, ACAC={acac}",
                    details="Authenticated GET requests readable from evil.com with credentials",
                    request={"Origin": "https://evil.com", "method": "GET"},
                    response={"ACAO": acao, "ACAC": acac},
                    duration_ms=duration,
                )
            elif acao in ("*", "https://evil.com"):
                return self._make_result(
                    variant="get_evil_origin",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"GET responds with ACAO={acao} (no credentials)",
                    details="GET responses readable from evil.com but without cookies",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao, "ACAC": acac or "not set"},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="get_evil_origin",
                    status=Status.DEFENDED,
                    evidence=f"ACAO: '{acao}' - evil origin not reflected",
                    details="GET CORS properly restricted",
                    request={"Origin": "https://evil.com"},
                    response={"ACAO": acao or "not set"},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="get_evil_origin",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def _test_credentials_header(self, client) -> AttackResult:
        """Check if Access-Control-Allow-Credentials is true on any endpoint."""
        start = time.monotonic()
        try:
            # Test multiple endpoints for credential exposure
            endpoints = [
                ("/api/ai_chat.php", {"action": "get_messages", "session_id": "redteam-cors-test"}),
                ("/api/ai_bearing_notes.php", {"action": "get_notes", "bearing_id": "test"}),
            ]

            credentials_found = False
            evidence_details = []

            for endpoint, params in endpoints:
                status_code, body, headers = await client.get(
                    endpoint,
                    params=params,
                    headers={"Origin": "https://evil.com"},
                )
                acac = headers.get("Access-Control-Allow-Credentials", "").lower()
                if acac == "true":
                    credentials_found = True
                    evidence_details.append(f"{endpoint}: ACAC=true")

            duration = (time.monotonic() - start) * 1000

            if credentials_found:
                return self._make_result(
                    variant="credentials_allowed",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=f"Credentials allowed on: {', '.join(evidence_details)}",
                    details="Access-Control-Allow-Credentials: true enables cookie-based cross-origin requests",
                    request={"checked_endpoints": [e[0] for e in endpoints]},
                    response={"findings": evidence_details},
                    duration_ms=duration,
                )
            else:
                return self._make_result(
                    variant="credentials_allowed",
                    status=Status.DEFENDED,
                    evidence="No endpoints return Access-Control-Allow-Credentials: true",
                    details="Cross-origin requests cannot include cookies",
                    request={"checked_endpoints": [e[0] for e in endpoints]},
                    response={"credentials_allowed": False},
                    duration_ms=duration,
                )
        except Exception as e:
            return self._make_result(
                variant="credentials_allowed",
                status=Status.ERROR,
                details=str(e),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    async def cleanup(self, client) -> None:
        """No persistent state created by CORS tests."""
        pass
```

---

## Step 6: Write redteam/attacks/web/session.py

Create `/opt/security-red-team/redteam/attacks/web/session.py`:

```python
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
```

---

## Step 7: Run tests to verify passes

```bash
cd /opt/security-red-team
source venv/bin/activate
python -m pytest tests/test_web_attacks.py -v
```

Expected: All tests pass.

---

## Step 8: Commit

```bash
cd /opt/security-red-team
git add redteam/attacks/web/xss.py redteam/attacks/web/csrf.py redteam/attacks/web/cors.py redteam/attacks/web/session.py tests/test_web_attacks.py
git commit -m "feat: add web attack modules for XSS, CSRF, CORS, and session security

- XSSAttack: 6 variants testing stored XSS via chat messages and bearing notes
- CSRFAttack: 3 variants testing Origin validation and CSRF token presence
- CORSAttack: 3 variants testing CORS header permissiveness and credential exposure
- SessionAttack: 3 variants checking HttpOnly, Secure, and SameSite cookie flags
- Comprehensive test suite with mock client covering all attack variants"
```

---

## Acceptance Criteria

- [ ] `tests/test_web_attacks.py` exists and covers all four attack classes
- [ ] Tests fail before implementation (TDD red phase)
- [ ] `redteam/attacks/web/xss.py` implements `XSSAttack` with 6 variants: script_tag, event_handler, svg_onload, markdown_javascript, html_entity_bypass, css_injection
- [ ] XSS evaluation checks for unescaped vs HTML-entity-escaped payload in response
- [ ] `redteam/attacks/web/csrf.py` implements `CSRFAttack` with 3 variants: no_origin_header, forged_origin, no_csrf_token
- [ ] CSRF tests use `client.post()` with controlled headers
- [ ] `redteam/attacks/web/cors.py` implements `CORSAttack` with 3 variants: preflight_evil_origin, get_evil_origin, credentials_allowed
- [ ] CORS evaluation distinguishes CRITICAL (wildcard + credentials) from HIGH (wildcard only)
- [ ] `redteam/attacks/web/session.py` implements `SessionAttack` with 3 variants: httponly_flag, secure_flag, samesite_attribute
- [ ] Session tests examine raw Set-Cookie header from login endpoint
- [ ] All attacks extend `Attack` base class and return `list[AttackResult]`
- [ ] All tests pass after implementation
- [ ] Changes committed with descriptive message
