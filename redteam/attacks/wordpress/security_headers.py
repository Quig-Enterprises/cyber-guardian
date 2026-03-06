"""WordPress HTTP security headers analysis — LOW severity.

Checks the homepage response for standard security headers that protect
against clickjacking, MIME sniffing, XSS, and other client-side attacks.

Each header is evaluated independently and produces its own result.
"""

import time
import logging

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)


class SecurityHeadersAttack(Attack):
    """Analyze HTTP security headers on the WordPress homepage."""

    name = "wordpress.security_headers"
    category = "wordpress"
    severity = Severity.LOW
    description = "HTTP security header presence and configuration analysis"
    target_types = {"wordpress"}

    async def execute(self, client) -> list[AttackResult]:
        """Fetch the homepage and check all security headers."""
        start = time.monotonic()
        try:
            status_code, body, headers = await client.get("/", cookies={})
            fetch_duration = (time.monotonic() - start) * 1000
        except Exception as e:
            return [self._make_result(
                variant="homepage_fetch",
                status=Status.ERROR,
                details=f"Failed to fetch homepage: {e}",
                duration_ms=(time.monotonic() - start) * 1000,
            )]

        if status_code >= 500:
            return [self._make_result(
                variant="homepage_fetch",
                status=Status.ERROR,
                details=f"Homepage returned HTTP {status_code}",
                response={"status": status_code},
                duration_ms=fetch_duration,
            )]

        # Normalize header keys to lowercase for reliable lookup
        norm = {k.lower(): v for k, v in headers.items()}

        results = []
        results.append(self._check_csp(norm, fetch_duration))
        results.append(self._check_hsts(norm, fetch_duration))
        results.append(self._check_x_frame_options(norm, fetch_duration))
        results.append(self._check_x_content_type_options(norm, fetch_duration))
        results.append(self._check_x_xss_protection(norm, fetch_duration))
        results.append(self._check_referrer_policy(norm, fetch_duration))
        results.append(self._check_permissions_policy(norm, fetch_duration))

        return results

    # ------------------------------------------------------------------
    # Individual header checks
    # ------------------------------------------------------------------

    def _check_csp(self, headers: dict, duration: float) -> AttackResult:
        """Content-Security-Policy — mitigates XSS and data injection."""
        value = headers.get("content-security-policy", "")
        if value:
            return self._make_result(
                variant="content_security_policy",
                status=Status.DEFENDED,
                evidence=f"CSP present: {value[:200]}",
                details="Content-Security-Policy header is set, reducing XSS attack surface.",
                response={"Content-Security-Policy": value[:200]},
                duration_ms=duration,
            )
        return self._make_result(
            variant="content_security_policy",
            status=Status.VULNERABLE,
            evidence="Content-Security-Policy header missing",
            details=(
                "No Content-Security-Policy header found. The site is more susceptible "
                "to XSS and data injection attacks without a CSP."
            ),
            response={"Content-Security-Policy": "not set"},
            duration_ms=duration,
        )

    def _check_hsts(self, headers: dict, duration: float) -> AttackResult:
        """Strict-Transport-Security — forces HTTPS connections."""
        value = headers.get("strict-transport-security", "")
        if not value:
            return self._make_result(
                variant="strict_transport_security",
                status=Status.VULNERABLE,
                evidence="Strict-Transport-Security header missing",
                details=(
                    "No HSTS header found. Browsers may connect over plain HTTP, "
                    "exposing users to downgrade and MITM attacks."
                ),
                response={"Strict-Transport-Security": "not set"},
                duration_ms=duration,
            )

        # Parse max-age
        max_age = 0
        for part in value.lower().replace(" ", "").split(";"):
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass

        if max_age < 31536000:
            return self._make_result(
                variant="strict_transport_security",
                status=Status.PARTIAL,
                evidence=f"HSTS max-age={max_age} (< 1 year)",
                details=(
                    f"Strict-Transport-Security is present but max-age is {max_age} seconds "
                    f"({max_age // 86400} days). Recommended minimum is 31536000 (1 year)."
                ),
                response={"Strict-Transport-Security": value},
                duration_ms=duration,
            )

        return self._make_result(
            variant="strict_transport_security",
            status=Status.DEFENDED,
            evidence=f"HSTS present with max-age={max_age}",
            details=f"Strict-Transport-Security header is properly configured: {value}",
            response={"Strict-Transport-Security": value},
            duration_ms=duration,
        )

    def _check_x_frame_options(self, headers: dict, duration: float) -> AttackResult:
        """X-Frame-Options — prevents clickjacking via iframes."""
        value = headers.get("x-frame-options", "").upper()
        if not value:
            return self._make_result(
                variant="x_frame_options",
                status=Status.VULNERABLE,
                evidence="X-Frame-Options header missing",
                details=(
                    "No X-Frame-Options header found. The page can be embedded in "
                    "iframes on any domain, enabling clickjacking attacks."
                ),
                response={"X-Frame-Options": "not set"},
                duration_ms=duration,
            )

        if value in ("DENY", "SAMEORIGIN"):
            return self._make_result(
                variant="x_frame_options",
                status=Status.DEFENDED,
                evidence=f"X-Frame-Options: {value}",
                details=f"X-Frame-Options is set to {value}, preventing clickjacking.",
                response={"X-Frame-Options": value},
                duration_ms=duration,
            )

        # ALLOW-FROM or unexpected value
        return self._make_result(
            variant="x_frame_options",
            status=Status.PARTIAL,
            evidence=f"X-Frame-Options: {value} (non-standard or permissive)",
            details=f"X-Frame-Options is set to '{value}'. Only DENY or SAMEORIGIN are recommended.",
            response={"X-Frame-Options": value},
            duration_ms=duration,
        )

    def _check_x_content_type_options(self, headers: dict, duration: float) -> AttackResult:
        """X-Content-Type-Options: nosniff — prevents MIME type sniffing."""
        value = headers.get("x-content-type-options", "").lower()
        if value == "nosniff":
            return self._make_result(
                variant="x_content_type_options",
                status=Status.DEFENDED,
                evidence="X-Content-Type-Options: nosniff",
                details="MIME type sniffing is disabled, reducing drive-by download risk.",
                response={"X-Content-Type-Options": "nosniff"},
                duration_ms=duration,
            )
        return self._make_result(
            variant="x_content_type_options",
            status=Status.VULNERABLE,
            evidence=f"X-Content-Type-Options: '{value or 'not set'}'",
            details=(
                "X-Content-Type-Options is missing or not set to 'nosniff'. "
                "Browsers may MIME-sniff responses, allowing attackers to disguise "
                "executable content as benign file types."
            ),
            response={"X-Content-Type-Options": value or "not set"},
            duration_ms=duration,
        )

    def _check_x_xss_protection(self, headers: dict, duration: float) -> AttackResult:
        """X-XSS-Protection — deprecated but still checked for legacy coverage."""
        value = headers.get("x-xss-protection", "")
        if value:
            return self._make_result(
                variant="x_xss_protection",
                status=Status.DEFENDED,
                severity=Severity.INFO,
                evidence=f"X-XSS-Protection: {value}",
                details=(
                    f"X-XSS-Protection is set to '{value}'. Note: this header is deprecated "
                    "in modern browsers (Chrome removed support in 2019). A strong CSP is the "
                    "preferred XSS mitigation."
                ),
                response={"X-XSS-Protection": value},
                duration_ms=duration,
            )
        return self._make_result(
            variant="x_xss_protection",
            status=Status.DEFENDED,
            severity=Severity.INFO,
            evidence="X-XSS-Protection header not set (deprecated header)",
            details=(
                "X-XSS-Protection is not set. This is acceptable as the header is deprecated "
                "in modern browsers. A Content-Security-Policy is the recommended replacement."
            ),
            response={"X-XSS-Protection": "not set"},
            duration_ms=duration,
        )

    def _check_referrer_policy(self, headers: dict, duration: float) -> AttackResult:
        """Referrer-Policy — controls how much referrer info is sent."""
        value = headers.get("referrer-policy", "")
        if not value:
            return self._make_result(
                variant="referrer_policy",
                status=Status.VULNERABLE,
                evidence="Referrer-Policy header missing",
                details=(
                    "No Referrer-Policy header found. The browser's default policy applies, "
                    "which may leak full URLs (including query parameters with tokens/IDs) "
                    "to third-party sites."
                ),
                response={"Referrer-Policy": "not set"},
                duration_ms=duration,
            )

        restrictive_policies = {
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "no-referrer-when-downgrade",
        }
        # A policy can contain multiple comma-separated fallback values
        policies = {p.strip().lower() for p in value.split(",")}
        is_restrictive = bool(policies & restrictive_policies)

        if is_restrictive:
            return self._make_result(
                variant="referrer_policy",
                status=Status.DEFENDED,
                evidence=f"Referrer-Policy: {value}",
                details=f"Referrer-Policy is set to a restrictive value: {value}",
                response={"Referrer-Policy": value},
                duration_ms=duration,
            )

        return self._make_result(
            variant="referrer_policy",
            status=Status.PARTIAL,
            evidence=f"Referrer-Policy: {value} (permissive)",
            details=(
                f"Referrer-Policy is set to '{value}', which may still leak referrer "
                f"information to cross-origin destinations."
            ),
            response={"Referrer-Policy": value},
            duration_ms=duration,
        )

    def _check_permissions_policy(self, headers: dict, duration: float) -> AttackResult:
        """Permissions-Policy (or Feature-Policy) — restricts browser features."""
        value = headers.get("permissions-policy", "") or headers.get("feature-policy", "")
        header_name = (
            "Permissions-Policy" if headers.get("permissions-policy")
            else "Feature-Policy" if headers.get("feature-policy")
            else "not set"
        )

        if value:
            return self._make_result(
                variant="permissions_policy",
                status=Status.DEFENDED,
                evidence=f"{header_name}: {value[:200]}",
                details=(
                    f"{header_name} is set, restricting access to browser features "
                    f"like camera, microphone, and geolocation."
                ),
                response={header_name: value[:200]},
                duration_ms=duration,
            )

        return self._make_result(
            variant="permissions_policy",
            status=Status.VULNERABLE,
            evidence="Permissions-Policy / Feature-Policy header missing",
            details=(
                "Neither Permissions-Policy nor Feature-Policy header is set. "
                "Third-party iframes and scripts may access browser features like "
                "camera, microphone, and geolocation without restriction."
            ),
            response={"Permissions-Policy": "not set", "Feature-Policy": "not set"},
            duration_ms=duration,
        )

    async def cleanup(self, client) -> None:
        """No persistent state created by header checks."""
        pass
