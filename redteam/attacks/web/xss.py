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
    target_types = {"app", "wordpress", "generic"}

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
        endpoints = self._get_test_endpoints()
        self._test_path = endpoints[0]
        self._note_path = endpoints[1] if len(endpoints) > 1 else endpoints[0]

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
            self._test_path,
            json_body={
                "action": "send_message",
                "message": payload,
                "session_id": session_id,
            },
        )

        # GET the messages back to check if payload is stored unsanitized
        get_status, get_body, get_headers = await client.get(
            self._test_path,
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
            self._note_path,
            json_body={
                "action": "add_note",
                "note": payload,
                "bearing_id": "redteam-xss-test",
            },
        )

        # GET the notes back
        get_status, get_body, get_headers = await client.get(
            self._note_path,
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
            await client.post(self._test_path, json_body={
                "action": "delete_session",
                "session_id_prefix": "redteam-xss-",
            })
        except Exception:
            pass
